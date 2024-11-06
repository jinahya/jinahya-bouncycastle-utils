package io.github.jinahya.bouncycastle.crypto;

import java.util.Objects;

@SuppressWarnings({
        "java:S119" // <ADAPTER>
})
public abstract class CipherAdapterTest<ADAPTER extends CipherAdapter> {

    protected CipherAdapterTest(final Class<ADAPTER> adapterClass) {
        super();
        this.adapterClass = Objects.requireNonNull(adapterClass, "adapterClass is null");
    }

    protected final Class<ADAPTER> adapterClass;
}