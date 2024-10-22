package io.github.jinahya.util.bouncycastle.jce.provider;

import java.security.Provider;

public final class _JinahyaBouncyCastleProviderUtils {

    private static final String BOUNCY_CASTLE_PROVIDER_NAME = "org.bouncycastle.jce.provider.BouncyCastleProvider";

    /**
     * Returns a new instance of {@value #BOUNCY_CASTLE_PROVIDER_NAME}.
     *
     * @return a new instance of {@value #BOUNCY_CASTLE_PROVIDER_NAME}.
     * @throws ReflectiveOperationException if failed to instantiate.
     */
    // when the bouncycastle is a runtime-scoped dependency.
    public static Provider getBouncyCastleProvider() throws ReflectiveOperationException {
        final Class<?> c = Class.forName(BOUNCY_CASTLE_PROVIDER_NAME);
        final var p = c.getConstructor().newInstance();
        assert p instanceof Provider;
        return (Provider) c.getConstructor().newInstance();
    }

    // -----------------------------------------------------------------------------------------------------------------
    private _JinahyaBouncyCastleProviderUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
