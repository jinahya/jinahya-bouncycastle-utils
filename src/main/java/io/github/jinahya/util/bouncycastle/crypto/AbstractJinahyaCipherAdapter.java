package io.github.jinahya.util.bouncycastle.crypto;

import org.bouncycastle.crypto.CipherParameters;

import java.util.Objects;

@SuppressWarnings({
        "java:S119" // <CIPHER>
})
public abstract class AbstractJinahyaCipherAdapter<CIPHER>
        implements JinahyaCipherAdapter {

    protected AbstractJinahyaCipherAdapter(final CIPHER cipher, final CipherParameters params) {
        super();
        this.cipher = Objects.requireNonNull(cipher, "cipher is null");
        this.params = Objects.requireNonNull(params, "params is null");
    }

    // -----------------------------------------------------------------------------------------------------------------
    protected final CIPHER cipher;

    protected final CipherParameters params;
}
