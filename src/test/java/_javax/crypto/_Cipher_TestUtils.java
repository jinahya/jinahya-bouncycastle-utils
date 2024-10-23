package _javax.crypto;

import io.github.jinahya.util._LogUtils;
import io.github.jinahya.util._RandomTestUtils;
import jdk.dynalink.linker.support.Lookup;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.nio.file.Path;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * .
 *
 * @see <a href="https://docs.oracle.com/en/java/javase/21/docs/specs/security/standard-names.html">Java Security
 * Standard Algorithm Names</a> (JDK 21 Documentation)
 */
public final class _Cipher_TestUtils {

//    public static void __(final Cipher cipher, final Object... arguments) throws Throwable {
//        Objects.requireNonNull(arguments, "arguments is null");
//        {
//            final var ptype0 = int.class;
//            final var ptypes = Arrays.stream(arguments).map(Object::getClass).toArray(i -> new Class<?>[i]);
//            final var methodType = MethodType.methodType(Void.class, ptype0, ptypes);
////            final var methodHandle = Lookup.PUBLIC.findVirtual(Cipher.class, "init", methodType);
//            final var methodHandle = MethodHandles.publicLookup().findVirtual(Cipher.class, "init", methodType);
//            final Object[] args = Stream.concat(
//                    Stream.of(cipher, Cipher.DECRYPT_MODE),
//                    Arrays.stream(arguments)
//            ).toArray();
//            final var result = methodHandle.invoke(args);
//            assertThat(result).isNull();
//        }
//        final var plain = _RandomTestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(1024));
//        final var encrypted = cipher.doFinal(plain);
//        {
//            final var ptype0 = int.class;
//            final var ptypes = Arrays.stream(arguments).map(Object::getClass).toArray(i -> new Class[0]);
//            final var methodType = MethodType.methodType(Void.class, ptype0, ptypes);
//            final var methodHandle = Lookup.PUBLIC.findVirtual(Cipher.class, "init", methodType);
//            final Object[] args = Stream.concat(
//                    Stream.of(cipher, Cipher.DECRYPT_MODE),
//                    Arrays.stream(arguments)
//            ).toArray();
//            final var result = methodHandle.invoke(args);
//            assertThat(result).isNull();
//        }
//        final var decrypted = cipher.doFinal(encrypted);
//        _LogUtils.log(plain, encrypted, decrypted);
//        assertThat(decrypted).isEqualTo(plain);
//    }

    public static void __(final Cipher cipher, final Key key, final AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException,
                   BadPaddingException {
        final var plain = _RandomTestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(1024));
        cipher.init(Cipher.ENCRYPT_MODE, key, params);
        final var encrypted = cipher.doFinal(plain);
        cipher.init(Cipher.DECRYPT_MODE, key, params);
        final var decrypted = cipher.doFinal(encrypted);
        _LogUtils.log(plain, encrypted, decrypted);
        assertThat(decrypted).isEqualTo(plain);
    }

    void __(final Path dir, final Cipher cipher, final Object... arguments) {
    }

    private _Cipher_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
