<?php

namespace Ocsp\Service;

final class Math
{
    private static $bigIntegerClass = '';

    /**
     * Set the name of the class for new BigInteger instances
     *
     * @param string|null $className can be 'phpseclib3\Math\BigInteger' or 'phpseclib\Math\BigInteger'. If an empty string (or NULL) is passed, we'll detect it automatically
     */
    public static function setBigIntegerClass($className)
    {
        self::$bigIntegerClass = (string) $className;
    }

    public static function getBigIntegerClass()
    {
        if (self::$bigIntegerClass === '') {
            self::$bigIntegerClass = 'phpseclib3\Math\BigInteger';
            if (!class_exists(self::$bigIntegerClass)) {
                self::$bigIntegerClass = 'phpseclib\Math\BigInteger';
            }
        }
        return self::$bigIntegerClass;
    }

    /**
     * @param string|int|resource|\phpseclib3\Math\BigInteger\Engines\Engine $x
     * @param int $base
     *
     * @return \phpseclib\Math\BigInteger|\phpseclib3\Math\BigInteger
     */
    public static function createBigInteger($x, $base = 10)
    {
        $class = self::getBigIntegerClass();

        return new $class($x, $base);
    }
}
