<?php

if (class_exists('phpseclib\Math\BigInteger')) {
    class_alias('phpseclib\Math\BigInteger', 'Ocsp\BigInteger');
} elseif (class_exists('phpseclib3\Math\BigInteger')) {
    class_alias('phpseclib3\Math\BigInteger', 'Ocsp\BigInteger');
}
