package io.github.srihrao214.jcespi.bc;

import io.github.srihrao214.jcespi.internal.HybridTextEncryption;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Uses Bouncy Castle for the cryptographic operations in the hybrid text encryption flow.
 * The provider object is passed directly to the Java cryptography engines, so creating this
 * implementation leaves the application's global provider list and its order intact.
 */
public final class BouncyCastleTextEncryption extends HybridTextEncryption {

    private static final BouncyCastleProvider PROVIDER = new BouncyCastleProvider();

    /** Creates an implementation using Bouncy Castle for ML-KEM, X25519, SHA3-256, and AES-GCM. */
    public BouncyCastleTextEncryption() {
        super(PROVIDER, PROVIDER, PROVIDER);
    }
}
