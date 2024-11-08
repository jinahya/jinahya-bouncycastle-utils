package io.github.jinahya.bouncycastle.miscellaneous;

import io.github.jinahya.bouncycastle.jce.provider.BouncyCastleProviderUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Objects;

final class SEED_Utils {

    private static boolean keyBytesMatchesAny(final int keyBytes) {
        return SEED_Constants.getKeyBytesStream().anyMatch(kb -> kb == keyBytes);
    }

    private static byte[] requireValidIv(final byte[] iv) {
        if (Objects.requireNonNull(iv, "iv is null").length != SEED_Constants.BLOCK_SIZE) {
            throw new IllegalArgumentException("iv.length(" + iv.length + ") != " + SEED_Constants.BLOCK_BYTES);
        }
        return iv;
    }

    private static byte[] doFinal(final String mode, final String padding, final byte[] key, final byte[] iv,
                                  final int opmode, final byte[] in)
            throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException,
                   InvalidAlgorithmParameterException, InvalidKeyException,
                   IllegalBlockSizeException, BadPaddingException {
        if (!keyBytesMatchesAny(Objects.requireNonNull(key, "key is null").length)) {
            throw new IllegalArgumentException("valid key.length(" + key.length + ")");
        }
        if (iv != null && iv.length != SEED_Constants.BLOCK_SIZE) {
            throw new IllegalArgumentException("iv.length(" + iv.length + ") != " + SEED_Constants.BLOCK_BYTES);
        }
        final var cipher = Cipher.getInstance(SEED_Constants.ALGORITHM + '/' + mode + '/' + padding,
                                              BouncyCastleProviderUtils.BOUNCY_CASTLE_PROVIDER_NAME);
        final var key_ = new SecretKeySpec(key, SEED_Constants.ALGORITHM);
        final var params = iv == null ? null : new IvParameterSpec(iv);
        if (params != null) {
            cipher.init(opmode, key_, params);
        } else {
            cipher.init(opmode, key_);
        }
        return cipher.doFinal(in);
    }

    public static byte[] encrypt_CBC_PKCS5Padding(final byte[] key, final byte[] iv, final byte[] in)
            throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException,
                   InvalidAlgorithmParameterException, InvalidKeyException,
                   IllegalBlockSizeException, BadPaddingException {
        if (Objects.requireNonNull(iv, "iv is null").length != SEED_Constants.BLOCK_SIZE) {
            throw new IllegalArgumentException("iv.length(" + iv.length + ") != " + SEED_Constants.BLOCK_BYTES);
        }
        return doFinal(
                "CBC",
                "PKCS5Padding",
                key,
                requireValidIv(iv),
                Cipher.ENCRYPT_MODE,
                in
        );
    }

    public static byte[] decrypt_CBC_PKCS5Padding(final byte[] key, final byte[] iv, final byte[] in)
            throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException,
                   InvalidAlgorithmParameterException, InvalidKeyException,
                   IllegalBlockSizeException, BadPaddingException {
        if (Objects.requireNonNull(iv, "iv is null").length != SEED_Constants.BLOCK_SIZE) {
            throw new IllegalArgumentException("iv.length(" + iv.length + ") != " + SEED_Constants.BLOCK_BYTES);
        }
        return doFinal(
                "CBC",
                "PKCS5Padding",
                key,
                requireValidIv(iv),
                Cipher.DECRYPT_MODE,
                in
        );
    }

    private SEED_Utils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
