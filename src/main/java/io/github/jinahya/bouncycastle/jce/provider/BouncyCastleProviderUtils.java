package io.github.jinahya.bouncycastle.jce.provider;

import java.security.Provider;
import java.security.Security;

/**
 * Utilities related to the {@value BouncyCastleProviderUtils#BOUNCY_CASTLE_PROVIDER_CLASS_NAME} class.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 */
public final class BouncyCastleProviderUtils {

    // ----------------------------------------------------------------------------------------------------------- class
    private static final String BOUNCY_CASTLE_PROVIDER_CLASS_NAME =
            "org.bouncycastle.jce.provider.BouncyCastleProvider";

    private static final Class<?> BOUNCY_CASTLE_PROVIDER_CLASS;

    static {
        try {
            BOUNCY_CASTLE_PROVIDER_CLASS = Class.forName(BOUNCY_CASTLE_PROVIDER_CLASS_NAME);
        } catch (final ReflectiveOperationException roe) {
            throw new ExceptionInInitializerError(
                    "failed to find the class for '" + BOUNCY_CASTLE_PROVIDER_CLASS_NAME + "'; " + roe.getMessage()
            );
        }
    }

    // -------------------------------------------------------------------------------------------------------- instance
    private static final Provider BOUNCY_CASTLE_PROVIDER;

    static {
        try {
            BOUNCY_CASTLE_PROVIDER = (Provider) BOUNCY_CASTLE_PROVIDER_CLASS.getConstructor().newInstance();
        } catch (final ReflectiveOperationException roe) {
            throw new ExceptionInInitializerError("failed to get provider;" + roe.getMessage());
        }
    }

    // ------------------------------------------------------------------------------------------------------------ name
    public static final String BOUNCY_CASTLE_PROVIDER_NAME = "BC";

    static {
        try {
            final var field = BOUNCY_CASTLE_PROVIDER_CLASS.getField("PROVIDER_NAME");
            assert field.canAccess(null);
            assert BOUNCY_CASTLE_PROVIDER_NAME.equals(field.get(null));
        } catch (final ReflectiveOperationException roe) {
            throw new ExceptionInInitializerError(roe.getMessage());
        }
    }

    // -----------------------------------------------------------------------------------------------------------------
    private static volatile boolean added = false;

    /**
     * Adds the {@value #BOUNCY_CASTLE_PROVIDER_NAME} provider to the {@link Security}.
     *
     * @see Security#addProvider(Provider)
     * @see #removeBouncyCastleProvider()
     */
    public static void addBouncyCastleProvider() {
        synchronized (BouncyCastleProviderUtils.class) {
            if (added) {
                return;
            }
            Security.addProvider(BOUNCY_CASTLE_PROVIDER);
            added = true;
        }
    }

    /**
     * Removes the {@value #BOUNCY_CASTLE_PROVIDER_NAME} provider from the {@link Security}.
     *
     * @see Security#removeProvider(String)
     * @see #addBouncyCastleProvider()
     */
    public static void removeBouncyCastleProvider() {
        synchronized (BouncyCastleProviderUtils.class) {
            Security.removeProvider(BOUNCY_CASTLE_PROVIDER_NAME);
            added = false;
        }
    }

    // -----------------------------------------------------------------------------------------------------------------
    private BouncyCastleProviderUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
