package io.github.jinahya.util.bouncycastle.jce.provider;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

import java.security.Provider;

import static org.assertj.core.api.Assertions.assertThat;

@Slf4j
class _JinahyaBouncyCastleProviderUtilsTest {

    @Test
    void getBouncyCastleProvider__() {
        final var provider = JinahyaBouncyCastleProviderUtils.getBouncyCastleProvider();
        assertThat(provider).isNotNull().isInstanceOf(Provider.class);
    }
}