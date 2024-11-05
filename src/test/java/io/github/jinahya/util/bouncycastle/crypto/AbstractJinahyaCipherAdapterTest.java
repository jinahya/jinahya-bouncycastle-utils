package io.github.jinahya.util.bouncycastle.crypto;

import java.util.Objects;

public abstract class AbstractJinahyaCipherAdapterTest<ADAPTER extends AbstractJinahyaCipherAdapter<CIPHER>, CIPHER>
        extends JinahyaCipherAdapterTest<ADAPTER> {

    protected AbstractJinahyaCipherAdapterTest(final Class<ADAPTER> adapterClass, final Class<CIPHER> cipherClass) {
        super(adapterClass);
        this.cipherClass = Objects.requireNonNull(cipherClass, "cipherClass is null");
    }

    // ---------------------------------------------------------------------------------------------------- adapterClass

    // ----------------------------------------------------------------------------------------------------- cipherClass

    // -----------------------------------------------------------------------------------------------------------------
    protected final Class<CIPHER> cipherClass;
}