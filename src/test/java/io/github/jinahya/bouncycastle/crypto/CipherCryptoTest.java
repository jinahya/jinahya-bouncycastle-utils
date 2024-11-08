package io.github.jinahya.bouncycastle.crypto;

import java.util.Objects;

public abstract class CipherCryptoTest<CRYPTO extends JinahyaCipherCrypto<CIPHER>, CIPHER>
        extends CryptoTest<CRYPTO> {

    protected CipherCryptoTest(final Class<CRYPTO> adapterClass, final Class<CIPHER> cipherClass) {
        super(adapterClass);
        this.cipherClass = Objects.requireNonNull(cipherClass, "cipherClass is null");
    }

    // ---------------------------------------------------------------------------------------------------- adapterClass

    // ----------------------------------------------------------------------------------------------------- cipherClass

    // -----------------------------------------------------------------------------------------------------------------
    protected final Class<CIPHER> cipherClass;
}