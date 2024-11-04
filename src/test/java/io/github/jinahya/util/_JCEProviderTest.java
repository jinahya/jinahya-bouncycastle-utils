package io.github.jinahya.util;

import io.github.jinahya.util.bouncycastle.jce.provider.JinahyaBouncyCastleProviderUtils;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;

@NoArgsConstructor(access = AccessLevel.PROTECTED)
public abstract class _JCEProviderTest {

    @BeforeAll
    static void beforeAll() {
        JinahyaBouncyCastleProviderUtils.addBouncyCastleProvider();
    }

    @AfterAll
    static void afterAll() {
        JinahyaBouncyCastleProviderUtils.removeBouncyCastleProvider();
    }
}
