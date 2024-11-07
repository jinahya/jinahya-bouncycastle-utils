package io.github.jinahya.bouncycastle.crypto;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.StreamCipher;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Objects;

/**
 * A utility class for {@link StreamCipher}.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 * @see <a
 * href="https://downloads.bouncycastle.org/java/docs/bcprov-jdk18on-javadoc/index.html?org/bouncycastle/crypto/StreamCipher.html">org.bouncycastle.crypto.StreamCipher</a>
 * (bcprov-jdk18on-javadoc)
 */
public final class JinahyaStreamCipherUtils {

    // -----------------------------------------------------------------------------------------------------------------
    public static byte[] processBytes(final StreamCipher cipher, final byte[] in, final int inoff, final int inlen) {
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(in, "in is null");
        for (var output = new byte[in.length == 0 ? 1 : in.length]; ; ) {
            try {
                final var processed = cipher.processBytes(in, inoff, inlen, output, 0);
                return Arrays.copyOf(output, processed);
            } catch (final DataLengthException dle) {
                System.err.println("doubling up output.length(" + output.length + ")");
                output = new byte[output.length << 1];
            }
        }
    }

    public static int processBytes(final StreamCipher cipher, final ByteBuffer input, final ByteBuffer output) {
        Objects.requireNonNull(input, "input is null");
        Objects.requireNonNull(output, "output is null");
        final byte[] in;
        final int inoff;
        final int inlen = input.remaining();
        if (input.hasArray()) {
            in = input.array();
            inoff = input.arrayOffset() + input.position();
        } else {
            in = new byte[inlen];
//            input.get(0, in); // Since 13
            for (int p = input.position(), i = 0; i < in.length; p++, i++) {
                in[i] = input.get(p);
            }
            inoff = 0;
        }
        final var out = processBytes(cipher, in, inoff, inlen);
        output.put(out);
        return out.length;
    }

    // -----------------------------------------------------------------------------------------------------------------
    public static long processAllBytes(final StreamCipher cipher, final InputStream in, final OutputStream out,
                                       final byte[] inbuf, byte[] outbuf)
            throws IOException {
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(in, "in is null");
        Objects.requireNonNull(out, "out is null");
        if (Objects.requireNonNull(inbuf, "inbuf is null").length == 0) {
            throw new IllegalArgumentException("inbuf.length is zero");
        }
        if (outbuf == null || outbuf.length == 0) {
            outbuf = new byte[inbuf.length];
        }
        var written = 0L;
        for (int outlen, r; (r = in.read(inbuf)) != -1; ) {
            while (true) {
                try {
                    outlen = cipher.processBytes(inbuf, 0, r, outbuf, 0);
                    out.write(outbuf, 0, outlen);
                    written += outlen;
                    break;
                } catch (final DataLengthException dle) {
                    System.err.println("doubling up outbuf.length(" + outbuf.length + ")");
                    Arrays.fill(outbuf, (byte) 0);
                    outbuf = new byte[outbuf.length << 1];
                }
            }
        }
        return written;
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaStreamCipherUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
