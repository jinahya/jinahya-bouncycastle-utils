package io.github.jinahya.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.modes.AEADCipher;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Objects;

/**
 * A utility class for {@link AEADCipher}.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 * @see JinahyaAEADCipherCrypto
 */
public final class JinahyaAEADCipherUtils {

    // -----------------------------------------------------------------------------------------------------------------
    public static int processBytesAndDoFinal(final AEADCipher cipher, final byte[] in, final int inoff, final int inlen,
                                             final byte[] out, final int outoff)
            throws InvalidCipherTextException {
        Objects.requireNonNull(cipher, "cipher is null");
        final var processed = cipher.processBytes(in, inoff, inlen, out, outoff); // DataLengthException
        final var finalized = cipher.doFinal(out, outoff + processed); // InvalidCipherTextException
        return processed + finalized;
    }

    public static int processBytesAndDoFinal(final AEADCipher cipher, final ByteBuffer input, final ByteBuffer output)
            throws InvalidCipherTextException {
        final byte[] in;
        final int inoff;
        final int inlen = input.remaining();
        if (input.hasArray()) {
            in = input.array();
            inoff = input.arrayOffset() + input.position();
        } else {
            in = new byte[inlen];
//            input.get(0, in); // Java 13
            for (int p = input.position(), i = 0; i < in.length; p++, i++) {
                in[i] = input.get(p);
            }
            inoff = 0;
        }
        final byte[] out;
        final int outoff;
        if (output.hasArray()) {
            out = output.array();
            outoff = output.arrayOffset() + output.position();
        } else {
            out = new byte[output.remaining()];
            outoff = 0;
        }
        final var outlen = processBytesAndDoFinal(cipher, in, inoff, inlen, out, outoff);
        input.position(input.position() + inlen);
        if (output.hasArray()) {
            output.position(output.position() + outlen);
        } else {
            output.put(out, outoff, outlen);
        }
        return outlen;
    }

    // -----------------------------------------------------------------------------------------------------------------
    public static long processAllBytesAndDoFinal(final AEADCipher cipher, final InputStream in, final OutputStream out,
                                                 final byte[] inbuf, byte[] outbuf)
            throws IOException, InvalidCipherTextException {
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(in, "in is null");
        Objects.requireNonNull(out, "out is null");
        if (Objects.requireNonNull(inbuf, "inbuf is null").length == 0) {
            throw new IllegalArgumentException("inbuf.length is zero");
        }
        if (outbuf == null || outbuf.length == 0) {
            outbuf = new byte[cipher.getOutputSize(inbuf.length)];
        }
//        var read = 0L;
        var written = 0L;
        for (int r; (r = in.read(inbuf)) != -1; ) {
            for (final var uos = cipher.getUpdateOutputSize(r); outbuf.length < uos; ) {
                System.err.println("re-allocating outbuf(" + outbuf.length +
                                           ") for an intermediate update-output-size(" + uos + ")");
                Arrays.fill(outbuf, (byte) 0);
                outbuf = new byte[uos];
            }
            final var outlen = cipher.processBytes(inbuf, 0, r, outbuf, 0); // DataLengthException
            out.write(outbuf, 0, outlen);
            written += outlen;
        }
//        for (final var os = cipher.getOutputSize(Math.toIntExact(read)); outbuf.length < os; ) {
        for (final var os = cipher.getOutputSize(0); outbuf.length < os; ) {
            System.err.println("re-allocating outbuf(" + outbuf.length + ") for the final output-size(" + os + ")");
            Arrays.fill(outbuf, (byte) 0);
            outbuf = new byte[os];
        }
        final var outlen = cipher.doFinal(outbuf, 0); // InvalidCipherTextException
        out.write(outbuf, 0, outlen);
        written += outlen;
        Arrays.fill(inbuf, (byte) 0);
        Arrays.fill(outbuf, (byte) 0);
        return written;
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaAEADCipherUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
