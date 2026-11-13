# Java cryptography providers

[![Build and tests](https://github.com/srihrao214/java-jce-spi/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/srihrao214/java-jce-spi/actions/workflows/build.yml)

This project demonstrates how the same Java text-encryption interface can run
on two cryptographic providers. Both implementations combine the post-quantum
ML-KEM-768 algorithm with the classical X25519 algorithm, then use AES-256-GCM
to encrypt and authenticate a UTF-8 string.

## Build and test

Use JDK 25 and Maven. The built-in ML-KEM implementation first shipped in
JDK 24. The build and CI workflow target Java 25.

```sh
java -version
mvn --batch-mode --no-transfer-progress clean verify
```

The build runs 10 JUnit 6 tests. The tests cover plaintext round trips, fresh
ciphertext on repeated encryption, empty input, rejection of tampered messages
and wrong keys, and interoperability in both directions.

## Maven modules

| Module | Responsibility |
| --- | --- |
| [crypto-api](crypto-api) | Defines the public `TextEncryption` contract and houses the shared encryption flow in the internal package. |
| [crypto-jdk](crypto-jdk) | Uses OpenJDK's SunJCE, SunEC, and SUN providers. |
| [crypto-bouncycastle](crypto-bouncycastle) | Uses the Bouncy Castle JCA/JCE provider and tests interoperability with the JDK implementation. |

A caller generates recipient keys, gives the public portion to the sender, and
keeps the full key pairs for decryption. The JDK round trip looks like this
inside a method that handles or declares `GeneralSecurityException`:

```java
TextEncryption encryption = new JdkTextEncryption();
var recipient = encryption.generateRecipientKeys();

byte[] message = encryption.encrypt("Grüße aus Heidelberg", recipient.publicKeys());
String plaintext = encryption.decrypt(message, recipient);
```

The same calls work with `BouncyCastleTextEncryption`. See the [JDK tests](crypto-jdk/src/test/java/io/github/srihrao214/jcespi/jdk/JdkTextEncryptionTest.java)
and [Bouncy Castle tests](crypto-bouncycastle/src/test/java/io/github/srihrao214/jcespi/bc/BouncyCastleTextEncryptionTest.java)
for complete examples.

## Message format

ML-KEM encapsulation produces a secret and an encapsulation that the recipient
can use to recover that secret. A fresh sender-side X25519 key pair supplies the
second secret. The project uses the [X-Wing draft's combiner](https://datatracker.ietf.org/doc/html/draft-connolly-cfrg-xwing-kem-11#section-5.3)
to turn the two secrets and the X25519 public values into a 32-byte AES key.

| Field | Size | Purpose |
| --- | ---: | --- |
| Format version | 1 byte | Identifies the demonstration format. |
| ML-KEM-768 encapsulation | 1,088 bytes | Lets the recipient recover the ML-KEM secret. |
| Ephemeral X25519 public value | 32 bytes | Lets the recipient calculate the X25519 secret. |
| AES-GCM nonce | 12 bytes | Supplies the per-message nonce. |
| AES-GCM ciphertext and tag | Variable | Contains encrypted text and a 16-byte authentication tag. |

AES-GCM authenticates the first four fields as associated data. The X-Wing
document is an Internet-Draft. The surrounding AES-GCM message format is
specific to this example. Sender authentication, trusted public-key distribution,
and private-key storage are outside the scope of the demo.

## Further reading

- [Service Provider Interfaces](docs/spi.md)
- [Provider SPIs in Java cryptography](docs/jce-spi.md)
- [OpenJDK JEP 496: ML-KEM](https://openjdk.org/jeps/496)

## License

The source and documentation in this repository are available under the
[Zero-Clause BSD license (0BSD)](LICENSE). Bouncy Castle is resolved separately
by Maven under its [own license](https://www.bouncycastle.org/licence.html).
