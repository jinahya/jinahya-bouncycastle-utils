package io.github.jinahya.util.bouncycastle.jce.provider;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import java.security.Provider;
import java.security.Security;

import static org.assertj.core.api.Assertions.assertThat;

@Slf4j
class _JinahyaBouncyCastleProviderUtilsTest {

    @Test
    void __() throws Exception {
        final var provider = JinahyaBouncyCastleProviderUtils.getBouncyCastleProvider();
        assertThat(provider).isNotNull().isInstanceOf(Provider.class);
        for (final var key : provider.keySet()) {
            log.debug("key: {}", key);
        }
        for (final var service : provider.getServices()) {
            log.debug("service: {}", service);
        }
        Security.addProvider(provider);
        final var got = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
        assertThat(got).hasSameClassAs(provider);
        assertThat(got).isSameAs(provider);
    }
}