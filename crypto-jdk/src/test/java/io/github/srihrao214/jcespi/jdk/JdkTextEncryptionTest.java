package io.github.srihrao214.jcespi.jdk;

import io.github.srihrao214.jcespi.api.TextEncryption;
import org.junit.jupiter.api.Test;

import java.security.GeneralSecurityException;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

class JdkTextEncryptionTest {

    private final TextEncryption encryption = new JdkTextEncryption();

    @Test
    void encryptsAndDecryptsUtf8Text() throws GeneralSecurityException {
        var recipient = encryption.generateRecipientKeys();
        String plaintext = "Grüße aus Heidelberg ☀";
        byte[] message = encryption.encrypt(plaintext, recipient.publicKeys());

        assertEquals(plaintext, encryption.decrypt(message, recipient));
        assertFalse(Arrays.equals(message, encryption.encrypt(plaintext, recipient.publicKeys())));
    }

    @Test
    void rejectsTamperedCiphertext() throws GeneralSecurityException {
        var recipient = encryption.generateRecipientKeys();
        byte[] message = encryption.encrypt("Hello", recipient.publicKeys());
        message[message.length - 1] ^= 1;

        assertThrows(GeneralSecurityException.class, () -> encryption.decrypt(message, recipient));
    }

    @Test
    void rejectsAnIncorrectRecipient() throws GeneralSecurityException {
        var recipient = encryption.generateRecipientKeys();
        var otherRecipient = encryption.generateRecipientKeys();
        byte[] message = encryption.encrypt("Hello", recipient.publicKeys());

        assertThrows(GeneralSecurityException.class, () -> encryption.decrypt(message, otherRecipient));
    }

    @Test
    void rejectsATruncatedHeader() throws GeneralSecurityException {
        var recipient = encryption.generateRecipientKeys();
        byte[] message = encryption.encrypt("Hello", recipient.publicKeys());
        byte[] truncated = Arrays.copyOf(message, 10);

        assertThrows(GeneralSecurityException.class, () -> encryption.decrypt(truncated, recipient));
    }
}
