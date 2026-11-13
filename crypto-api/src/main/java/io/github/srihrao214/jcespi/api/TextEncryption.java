package io.github.srihrao214.jcespi.api;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;

/**
 * Encrypts text for a recipient using ML-KEM-768 and X25519.
 * The sender uses the recipient's public keys. The recipient keeps the full key pairs.
 */
public interface TextEncryption {

    /**
     * Generates a new pair of keys for each of the two algorithms.
     *
     * @return the recipient's key pairs
     * @throws GeneralSecurityException if key generation fails
     */
    RecipientKeyPairs generateRecipientKeys() throws GeneralSecurityException;

    /**
     * Encodes the plaintext as UTF-8 and encrypts it for the recipient.
     *
     * @param plaintext the text to encrypt
     * @param recipient the recipient's public keys
     * @return the binary encrypted message
     * @throws GeneralSecurityException if encryption fails
     */
    byte[] encrypt(String plaintext, RecipientPublicKeys recipient)
            throws GeneralSecurityException;

    /**
     * Authenticates and decrypts an encrypted message and decodes the UTF-8 text.
     *
     * @param message the binary message returned by {@link #encrypt}
     * @param recipient the recipient's key pairs
     * @return the original plaintext
     * @throws GeneralSecurityException if the message is invalid or decryption fails
     */
    String decrypt(byte[] message, RecipientKeyPairs recipient)
            throws GeneralSecurityException;

    /**
     * The key material a recipient can share with senders.
     *
     * @param mlKem the ML-KEM-768 public key
     * @param x25519 the X25519 public key
     */
    record RecipientPublicKeys(PublicKey mlKem, PublicKey x25519) {}

    /**
     * The key material held by the recipient for decryption.
     *
     * @param mlKem the ML-KEM-768 key pair
     * @param x25519 the X25519 key pair
     */
    record RecipientKeyPairs(KeyPair mlKem, KeyPair x25519) {

        /**
         * Extracts the public keys that a sender needs to encrypt a message.
         *
         * @return the public portion of each key pair
         */
        public RecipientPublicKeys publicKeys() {
            return new RecipientPublicKeys(mlKem.getPublic(), x25519.getPublic());
        }
    }
}