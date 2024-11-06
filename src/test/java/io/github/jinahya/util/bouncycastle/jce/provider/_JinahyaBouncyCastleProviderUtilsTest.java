package io.github.jinahya.util.bouncycastle.jce.provider;

import io.github.jinahya.bouncycastle.jce.provider.BouncyCastleProviderUtils;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatCode;

@Slf4j
class _JinahyaBouncyCastleProviderUtilsTest {

    @Test
    void addBouncyCastleProvider__() {
        assertThatCode(BouncyCastleProviderUtils::addBouncyCastleProvider).doesNotThrowAnyException();
        assertThatCode(BouncyCastleProviderUtils::addBouncyCastleProvider).doesNotThrowAnyException();
    }

    @Test
    void removeBouncyCastleProvider__() {
        assertThatCode(BouncyCastleProviderUtils::removeBouncyCastleProvider).doesNotThrowAnyException();
        assertThatCode(BouncyCastleProviderUtils::removeBouncyCastleProvider).doesNotThrowAnyException();
    }

    @Test
    void __() {
        assertThatCode(BouncyCastleProviderUtils::addBouncyCastleProvider).doesNotThrowAnyException();
        assertThatCode(BouncyCastleProviderUtils::removeBouncyCastleProvider).doesNotThrowAnyException();
    }
}