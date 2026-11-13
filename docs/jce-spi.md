# Service providers in Java cryptography

Java Cryptography Architecture (JCA) supplies provider-based cryptography
through engine classes. The Java Cryptography Extension (JCE) is part of that
framework and supplies APIs in `javax.crypto` such as `Cipher` for encryption,
`KEM` for key encapsulation, and `KeyAgreement` for agreeing on a shared
secret.

| Layer | Role | Example |
| --- | --- | --- |
| Engine API | Gives application code a stable entry point. | `Cipher.getInstance("AES/GCM/NoPadding", provider)` |
| Provider registration | Advertises available algorithms and the implementations backing them. | `java.security.Provider` and its `Provider.Service` entries |
| Engine SPI | Defines the provider-side operations called by the engine. | `CipherSpi`, `KEMSpi`, `KeyAgreementSpi` |

A call to `getInstance` requests an algorithm or transformation. The engine
uses the selected provider's registered service to obtain an implementation.
For example, a cipher engine delegates initialization and final processing to
the implementation behind `CipherSpi`. The application works with `Cipher`
methods such as `init` and `doFinal`.

When the caller omits the provider, JCA consults eligible registered
providers. Some engines can defer the final choice until the key is supplied.
An explicit provider makes the choice visible and reproducible. A caller may
also pass a `Provider` object directly to the engine without changing the JVM's
global provider configuration.

## How the modules select providers

| Operation | Built-in JDK module | Bouncy Castle module |
| --- | --- | --- |
| ML-KEM-768 key generation and encapsulation | SunJCE | BC |
| X25519 key generation and agreement | SunEC | BC |
| SHA3-256 combiner | SUN | BC |
| AES-256-GCM | SunJCE | BC |

`HybridTextEncryption` passes the chosen provider objects to the engine
factories. `JdkTextEncryption` retrieves the named OpenJDK providers already
available in the runtime. `BouncyCastleTextEncryption` creates a
`BouncyCastleProvider` instance and passes it directly to the same flow.

This project consumes existing cryptographic providers. Their SPI classes
implement the algorithms. The project's shared interface defines the higher-level
operations that callers and tests use: generate keys, encrypt text, and decrypt
a message. The cross-provider tests show that both provider configurations can
read the project's common format.

- [JCA reference guide](https://docs.oracle.com/en/java/javase/25/security/java-cryptography-architecture-jca-reference-guide.html)
- [JDK provider documentation](https://docs.oracle.com/en/java/javase/25/security/oracle-providers.html)
- [Java 25 Cipher API](https://docs.oracle.com/en/java/javase/25/docs/api/java.base/javax/crypto/Cipher.html)
- [Java 25 KEM API](https://docs.oracle.com/en/java/javase/25/docs/api/java.base/javax/crypto/KEM.html)
