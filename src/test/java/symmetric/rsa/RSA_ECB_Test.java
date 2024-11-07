package symmetric.rsa;

import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.SecureRandom;

class RSA_ECB_Test
        extends RSA_Test {

    @Nested
    class LowLevelApiTest {

        @Test
        void __() throws Exception {
            final var keyPairGenerator = new RSAKeyPairGenerator();
            {
                final var params = new RSAKeyGenerationParameters(
                        new BigInteger("10001", 16),
                        SecureRandom.getInstanceStrong(),
                        1024,
                        80
                );
                keyPairGenerator.init(params);
            }
            final var keyPair = keyPairGenerator.generateKeyPair();
            final var cipher = new PKCS1Encoding(new RSAEngine());
            final var plain = new byte[10];
            // ------------------------------------------------------------------------------------------------ encoding
            cipher.init(true, keyPair.getPublic());
            final var encrypted = cipher.processBlock(plain, 0, plain.length);
        }
    }

    @Nested
    class JCETest {

    }
}
