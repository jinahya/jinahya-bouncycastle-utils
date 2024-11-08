package io.github.jinahya.bouncycastle.crypto;

import org.bouncycastle.crypto.CipherParameters;

import java.util.Objects;

/**
 * An abstract crypto clas for a specified type of cipher.
 *
 * @param <CIPHER> cipher type parameter
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 */
@SuppressWarnings({
        "java:S119" // <CIPHER>
})
public abstract class JinahyaCipherCrypto<CIPHER>
        implements JinahyaCrypto {

    /**
     * Creates a new instance with specified cipher and initialization parameters.
     *
     * @param cipher the cipher.
     * @param params the params.
     * @see #cipher
     * @see #params
     */
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

    /**
     * a cipher to use.
     */
    protected final CIPHER cipher;

    /**
     * a cipher parameters for initializing {@link #cipher}.
     */
    protected final CipherParameters params;
}
