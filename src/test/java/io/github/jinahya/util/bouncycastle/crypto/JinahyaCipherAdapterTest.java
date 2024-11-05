package io.github.jinahya.util.bouncycastle.crypto;

import java.util.Objects;

@SuppressWarnings({
        "java:S119" // <ADAPTER>
})
public abstract class JinahyaCipherAdapterTest<ADAPTER extends JinahyaCipherAdapter> {

    protected JinahyaCipherAdapterTest(final Class<ADAPTER> adapterClass) {
        super();
        this.adapterClass = Objects.requireNonNull(adapterClass, "adapterClass is null");
    }

    protected final Class<ADAPTER> adapterClass;
}