package io.github.jinahya.bouncycastle.crypto;

import org.bouncycastle.crypto.CipherParameters;

import java.util.Objects;

@SuppressWarnings({
        "java:S119" // <CIPHER>
})
public abstract class JinahyaCipherCrypto<CIPHER>
        implements JinahyaCrypto {

    protected JinahyaCipherCrypto(final CIPHER cipher, final CipherParameters params) {
        super();
        this.cipher = Objects.requireNonNull(cipher, "cipher is null");
        this.params = Objects.requireNonNull(params, "params is null");
    }

    // ---------------------------------------------------------------------------------------------------------- cipher

    /**
     * Initialize the {@link #cipher} for specified boolean flag of encryption.
     *
     * @param encryption {@code true} for encryption; {@code false} for decryption.
     */
    protected abstract void initFor(final boolean encryption);

    /**
     * Initialize the {@link #cipher} for encryption.
     */
    protected void initForEncryption() {
        initFor(true);
    }

    /**
     * Initialize the {@link #cipher} for decryption.
     */
    protected void initForDecryption() {
        initFor(false);
    }

    // -----------------------------------------------------------------------------------------------------------------
    protected final CIPHER cipher;

    protected final CipherParameters params;
}
