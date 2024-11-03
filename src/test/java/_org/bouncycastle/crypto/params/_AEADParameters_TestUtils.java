package _org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.params.AEADParameters;

import java.util.Objects;
import java.util.Optional;

public final class _AEADParameters_TestUtils {

    public static String associatedTextName(final byte[] associatedText) {
        final var formatted = Optional.ofNullable(associatedText)
                .filter(v -> v.length > 0)
                .map(v -> String.format("%1$02x", v[0]))
                .orElse("<none/empty>");
        return String.format("associatedText(%1$s)", formatted);
    }

    public static String paramsName(final AEADParameters params) {
        Objects.requireNonNull(params, "params is null");
        return _KeyParameters_TestUtils.paramsName(params.getKey()) +
                " with " +
                associatedTextName(params.getAssociatedText());
    }

    private _AEADParameters_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
