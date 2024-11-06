package io.github.jinahya.bouncycastle.crypto;

public class JinahyaCryptoException
        extends RuntimeException {

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
