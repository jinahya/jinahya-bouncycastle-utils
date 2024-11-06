package io.github.jinahya.bouncycastle.crypto;

import java.util.Objects;

public abstract class AbstractCipherAdapterTest<ADAPTER extends AbstractCipherAdapter<CIPHER>, CIPHER>
        extends CipherAdapterTest<ADAPTER> {

    protected AbstractCipherAdapterTest(final Class<ADAPTER> adapterClass, final Class<CIPHER> cipherClass) {
        super(adapterClass);
        this.cipherClass = Objects.requireNonNull(cipherClass, "cipherClass is null");
    }

    // ---------------------------------------------------------------------------------------------------- adapterClass

    // ----------------------------------------------------------------------------------------------------- cipherClass

    // -----------------------------------------------------------------------------------------------------------------
    protected final Class<CIPHER> cipherClass;
}