package io.github.jinahya.util;

import io.github.jinahya.bouncycastle.jce.provider.BouncyCastleProviderUtils;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;

@NoArgsConstructor(access = AccessLevel.PROTECTED)
public abstract class _JCEProviderTest {

    @BeforeAll
    static void beforeAll() {
        BouncyCastleProviderUtils.addBouncyCastleProvider();
    }

    @AfterAll
    static void afterAll() {
        BouncyCastleProviderUtils.removeBouncyCastleProvider();
    }
}
