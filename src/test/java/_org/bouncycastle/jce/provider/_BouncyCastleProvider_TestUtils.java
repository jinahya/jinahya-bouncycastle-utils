package _org.bouncycastle.jce.provider;

import java.security.Provider;

public final class _BouncyCastleProvider_TestUtils {

    // when the bouncycastle is a runtime-scoped dependency.
    public static Provider getBouncyCastleProvider() throws Exception {
        final Class<?> c = Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
        return Provider.class.cast(c.getConstructor().newInstance());
    }

    private _BouncyCastleProvider_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
