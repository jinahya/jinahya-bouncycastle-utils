package io.github.jinahya.util.kisa;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.util.stream.IntStream;

@NoArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
abstract class SEED__Test {

    static IntStream getKeySizeStream() {
        return IntStream.of(
                128
//                ,
//                196,
//                256
        );
    }

}
