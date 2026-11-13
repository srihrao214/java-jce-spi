package io.github.srihrao214.jcespi.internal;

import io.github.srihrao214.jcespi.api.TextEncryption;

import javax.crypto.Cipher;
import javax.crypto.KEM;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;

/**
 * Shared implementation of the demo message format and hybrid encryption flow.
 * Subclasses select the providers that supply the cryptographic operations.
 *
 * <p>The binary message contains a version byte, an ML-KEM-768 encapsulation,
 * a raw ephemeral X25519 public key, a 12-byte nonce, and the AES-GCM ciphertext
 * with its authentication tag. AES-GCM authenticates the complete header.
 */
public abstract class HybridTextEncryption implements TextEncryption {

    private static final byte FORMAT_VERSION = 1;
    private static final int ML_KEM_ENCAPSULATION_BYTES = 1088;
    private static final int X25519_PUBLIC_KEY_BYTES = 32;
    private static final int GCM_NONCE_BYTES = 12;
    private static final int GCM_TAG_BITS = 128;
    private static final int HEADER_BYTES = 1 + ML_KEM_ENCAPSULATION_BYTES
            + X25519_PUBLIC_KEY_BYTES + GCM_NONCE_BYTES;

    // RFC 8410 SubjectPublicKeyInfo prefix for a 32-byte raw X25519 public key.
    private static final byte[] X25519_SPKI_PREFIX = HexFormat.of().parseHex("302a300506032b656e032100");
    // Domain separator from section 5.3 of draft-connolly-cfrg-xwing-kem-11.
    private static final byte[] X_WING_LABEL = HexFormat.of().parseHex("5c2e2f2f5e5c");

    private final Provider kemAndCipherProvider;
    private final Provider x25519Provider;
    private final Provider digestProvider;
    private final SecureRandom random = new SecureRandom();

    /**
     * Selects the providers explicitly so each implementation exercises its chosen engines.
     *
     * @param kemAndCipherProvider the provider for ML-KEM and AES-GCM
     * @param x25519Provider the provider for X25519 keys and agreement
     * @param digestProvider the provider for SHA3-256
     */
    protected HybridTextEncryption(Provider kemAndCipherProvider, Provider x25519Provider,
                                   Provider digestProvider) {
        this.kemAndCipherProvider = Objects.requireNonNull(kemAndCipherProvider);
        this.x25519Provider = Objects.requireNonNull(x25519Provider);
        this.digestProvider = Objects.requireNonNull(digestProvider);
    }

    @Override
    public final RecipientKeyPairs generateRecipientKeys() throws GeneralSecurityException {
        var mlKem = KeyPairGenerator.getInstance("ML-KEM-768", kemAndCipherProvider).generateKeyPair();
        return new RecipientKeyPairs(mlKem, KeyPairGenerator.getInstance("X25519", x25519Provider)
                .generateKeyPair());
    }

    @Override
    public final byte[] encrypt(String plaintext, RecipientPublicKeys recipient)
            throws GeneralSecurityException {
        byte[] plaintextBytes;
        try {
            ByteBuffer utf8 = StandardCharsets.UTF_8.newEncoder().encode(CharBuffer.wrap(plaintext));
            plaintextBytes = new byte[utf8.remaining()];
            utf8.get(plaintextBytes);
        } catch (CharacterCodingException e) {
            throw new GeneralSecurityException("Plaintext cannot be encoded as UTF-8", e);
        }

        var ephemeral = KeyPairGenerator.getInstance("X25519", x25519Provider).generateKeyPair();
        byte[] ephemeralPublic = rawX25519(ephemeral.getPublic());
        byte[] recipientPublic = rawX25519(recipient.x25519());
        // Import public keys through their standard encodings for provider interoperability.
        var mlKemPublic = KeyFactory.getInstance("ML-KEM-768", kemAndCipherProvider)
                .generatePublic(new X509EncodedKeySpec(recipient.mlKem().getEncoded()));
        var encapsulated = KEM.getInstance("ML-KEM", kemAndCipherProvider)
                .newEncapsulator(mlKemPublic).encapsulate();
        byte[] nonce = new byte[GCM_NONCE_BYTES];
        random.nextBytes(nonce);
        byte[] header = ByteBuffer.allocate(HEADER_BYTES)
                .put(FORMAT_VERSION)
                .put(encapsulated.encapsulation())
                .put(ephemeralPublic)
                .put(nonce)
                .array();

        var key = combine(encapsulated.key().getEncoded(), ephemeral.getPrivate(),
                recipientPublic, ephemeralPublic, recipientPublic);
        byte[] ciphertext = gcm(Cipher.ENCRYPT_MODE, key, nonce, header).doFinal(plaintextBytes);
        return ByteBuffer.allocate(header.length + ciphertext.length).put(header).put(ciphertext).array();
    }

    @Override
    public final String decrypt(byte[] message, RecipientKeyPairs recipient)
            throws GeneralSecurityException {
        if (message.length < HEADER_BYTES + GCM_TAG_BITS / Byte.SIZE || message[0] != FORMAT_VERSION) {
            throw new GeneralSecurityException("Invalid or unsupported encrypted message");
        }

        byte[] header = Arrays.copyOf(message, HEADER_BYTES);
        var fields = ByteBuffer.wrap(header).position(1);
        byte[] encapsulation = new byte[ML_KEM_ENCAPSULATION_BYTES];
        byte[] ephemeralPublic = new byte[X25519_PUBLIC_KEY_BYTES];
        byte[] nonce = new byte[GCM_NONCE_BYTES];
        fields.get(encapsulation).get(ephemeralPublic).get(nonce);
        byte[] recipientPublic = rawX25519(recipient.x25519().getPublic());
        var mlKemSecret = KEM.getInstance("ML-KEM", kemAndCipherProvider)
                .newDecapsulator(recipient.mlKem().getPrivate()).decapsulate(encapsulation);

        var key = combine(mlKemSecret.getEncoded(), recipient.x25519().getPrivate(),
                ephemeralPublic, ephemeralPublic, recipientPublic);
        byte[] plaintext = gcm(Cipher.DECRYPT_MODE, key, nonce, header)
                .doFinal(message, HEADER_BYTES, message.length - HEADER_BYTES);
        try {
            return StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(plaintext)).toString();
        } catch (CharacterCodingException e) {
            throw new GeneralSecurityException("Decrypted text is not valid UTF-8", e);
        }
    }

    /**
     * Applies the X-Wing draft combiner to the two secrets and the raw X25519 public keys.
     * The output is a 32-byte AES key for this demo message format.
     */
    private SecretKeySpec combine(byte[] mlKemSecret, PrivateKey localX25519, byte[] peerX25519,
                                  byte[] ephemeralPublic, byte[] recipientPublic)
            throws GeneralSecurityException {
        try {
            byte[] spki = ByteBuffer.allocate(X25519_SPKI_PREFIX.length + X25519_PUBLIC_KEY_BYTES)
                    .put(X25519_SPKI_PREFIX).put(peerX25519).array();
            var peer = KeyFactory.getInstance("X25519", x25519Provider)
                    .generatePublic(new X509EncodedKeySpec(spki));
            var agreement = KeyAgreement.getInstance("X25519", x25519Provider);
            agreement.init(localX25519);
            agreement.doPhase(peer, true);
            byte[] x25519Secret = agreement.generateSecret();
            try {
                var sha3 = MessageDigest.getInstance("SHA3-256", digestProvider);
                sha3.update(mlKemSecret);
                sha3.update(x25519Secret);
                sha3.update(ephemeralPublic);
                sha3.update(recipientPublic);
                byte[] key = sha3.digest(X_WING_LABEL);
                try {
                    return new SecretKeySpec(key, "AES");
                } finally {
                    Arrays.fill(key, (byte) 0);
                }
            } finally {
                Arrays.fill(x25519Secret, (byte) 0);
            }
        } finally {
            Arrays.fill(mlKemSecret, (byte) 0);
        }
    }

    /** Extracts the 32-byte X25519 public value from its standard public-key encoding. */
    private static byte[] rawX25519(PublicKey key) throws InvalidKeyException {
        byte[] encoded = key.getEncoded();
        int prefixBytes = X25519_SPKI_PREFIX.length;
        if (encoded == null || encoded.length != prefixBytes + X25519_PUBLIC_KEY_BYTES
                || !Arrays.equals(encoded, 0, prefixBytes, X25519_SPKI_PREFIX, 0, prefixBytes)) {
            throw new InvalidKeyException("Expected an RFC 8410 X25519 public key");
        }
        return Arrays.copyOfRange(encoded, prefixBytes, encoded.length);
    }

    private Cipher gcm(int mode, SecretKeySpec key, byte[] nonce, byte[] header)
            throws GeneralSecurityException {
        var cipher = Cipher.getInstance("AES/GCM/NoPadding", kemAndCipherProvider);
        cipher.init(mode, key, new GCMParameterSpec(GCM_TAG_BITS, nonce));
        cipher.updateAAD(header);
        return cipher;
    }
}
