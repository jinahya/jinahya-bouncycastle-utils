package _org.bouncycastle.jce.provider;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import java.security.Provider;
import java.util.stream.Collectors;

@Slf4j
class _BouncyCastleProvider_Test {

    @Test
    void __keySet() {
        final var provider = (Provider) new BouncyCastleProvider();
        for (final var key : provider.keySet()) {
//            log.debug("key: {} {}", key, key.getClass());
        }
    }

    @Test
    void __getServices() {
        final var provider = (Provider) new BouncyCastleProvider();
        final var collected = provider.getServices().stream().collect(Collectors.groupingBy(Provider.Service::getType));
        for (final var entry : collected.entrySet()) {
            for (final var service : entry.getValue()) {
//                log.debug("type: {},\t\tservice: {}", entry.getKey(), service);
//                System.out.printf("type: %1$s\t\t%2$s%n", entry.getKey(), service);
            }
        }
    }
}




