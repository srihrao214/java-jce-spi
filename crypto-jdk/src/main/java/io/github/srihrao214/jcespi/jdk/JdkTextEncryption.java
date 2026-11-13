package io.github.srihrao214.jcespi.jdk;

import io.github.srihrao214.jcespi.internal.HybridTextEncryption;

import java.security.Security;

/**
 * Encrypts text with the providers bundled with OpenJDK.
 * SunJCE supplies ML-KEM and AES-GCM, SunEC supplies X25519, and SUN supplies SHA3-256.
 */
public final class JdkTextEncryption extends HybridTextEncryption {

    /** Creates an implementation using the built-in OpenJDK providers. */
    public JdkTextEncryption() {
        super(Security.getProvider("SunJCE"), Security.getProvider("SunEC"), Security.getProvider("SUN"));
    }
}
