package io.github.srihrao214.jcespi.bc;

import io.github.srihrao214.jcespi.api.TextEncryption;
import io.github.srihrao214.jcespi.jdk.JdkTextEncryption;
import org.junit.jupiter.api.Test;

import java.security.GeneralSecurityException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class BouncyCastleTextEncryptionTest {

    private final TextEncryption bouncyCastle = new BouncyCastleTextEncryption();

    @Test
    void encryptsAndDecryptsUtf8Text() throws GeneralSecurityException {
        assertRoundTrip(bouncyCastle, bouncyCastle, "Grüße aus Heidelberg ☀");
    }

    @Test
    void encryptsAndDecryptsAnEmptyString() throws GeneralSecurityException {
        assertRoundTrip(bouncyCastle, bouncyCastle, "");
    }

    @Test
    void rejectsTamperedCiphertext() throws GeneralSecurityException {
        var recipient = bouncyCastle.generateRecipientKeys();
        byte[] message = bouncyCastle.encrypt("Hello", recipient.publicKeys());
        message[message.length - 1] ^= 1;

        assertThrows(GeneralSecurityException.class, () -> bouncyCastle.decrypt(message, recipient));
    }

    @Test
    void rejectsAnIncorrectRecipient() throws GeneralSecurityException {
        var recipient = bouncyCastle.generateRecipientKeys();
        var otherRecipient = bouncyCastle.generateRecipientKeys();
        byte[] message = bouncyCastle.encrypt("Hello", recipient.publicKeys());

        assertThrows(GeneralSecurityException.class, () -> bouncyCastle.decrypt(message, otherRecipient));
    }

    @Test
    void jdkDecryptsAMessageEncryptedByBouncyCastle() throws GeneralSecurityException {
        assertRoundTrip(bouncyCastle, new JdkTextEncryption(), "Bouncy Castle to JDK");
    }

    @Test
    void bouncyCastleDecryptsAMessageEncryptedByJdk() throws GeneralSecurityException {
        assertRoundTrip(new JdkTextEncryption(), bouncyCastle, "JDK to Bouncy Castle");
    }

    private static void assertRoundTrip(TextEncryption sender, TextEncryption recipient,
                                        String plaintext) throws GeneralSecurityException {
        var recipientKeys = recipient.generateRecipientKeys();
        byte[] message = sender.encrypt(plaintext, recipientKeys.publicKeys());

        assertEquals(plaintext, recipient.decrypt(message, recipientKeys));
    }
}
