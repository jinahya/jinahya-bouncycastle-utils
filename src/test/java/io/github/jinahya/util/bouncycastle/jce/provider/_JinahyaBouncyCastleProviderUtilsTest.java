package io.github.jinahya.util.bouncycastle.jce.provider;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class _JinahyaBouncyCastleProviderUtilsTest {

    @Test
    void __() throws Exception {
        final var provider = _JinahyaBouncyCastleProviderUtils.getBouncyCastleProvider();
        assertThat(provider).isNotNull();
    }
}