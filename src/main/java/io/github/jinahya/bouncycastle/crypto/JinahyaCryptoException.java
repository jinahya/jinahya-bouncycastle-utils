package io.github.jinahya.bouncycastle.crypto;

public class JinahyaCryptoException
        extends RuntimeException {

    public static JinahyaCryptoException ofEncryptionFailure(final Throwable cause) {
        return new JinahyaCryptoException("failed to encrypt", cause);
    }

    public static JinahyaCryptoException ofDecryptionFailure(final Throwable cause) {
        return new JinahyaCryptoException("failed to decrypt", cause);
    }

    // -----------------------------------------------------------------------------------------------------------------
    public JinahyaCryptoException(final String message) {
        super(message);
    }

    public JinahyaCryptoException(final Throwable cause) {
        super(cause);
    }

    public JinahyaCryptoException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
