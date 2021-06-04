<?php

declare(strict_types = 1);

namespace Ocsp\Asn1\Util;

/**
 * Class to wrap an integer of arbirtary length.
 */
class BigInteger
{
    /**
     * Number as a GMP object.
     *
     * @var \GMP
     */
    private $_gmp;

    /**
     * Number as a base 10 integer string.
     *
     * @internal Lazily initialized
     *
     * @var null|string
     */
    private $_num;

    /**
     * Number as an integer type.
     *
     * @internal Lazily initialized
     *
     * @var null|int
     */
    private $_intNum;

    /**
     * Constructor.
     *
     * @param \GMP|int|string $num Integer number in base $base
     * @param int $base (optional: default = 10)
     */
    public function __construct( $num )
    {
        // convert to GMP object
        if ( ! ( $num instanceof \GMP) ) 
        {
            $gmp = @gmp_import( $num );
            if ( false === $gmp ) 
            {
                throw new \InvalidArgumentException( "Unable to convert '{$num}'" );
            }
            $num = $gmp;
        }
        $this->_gmp = $num;
    }

    public function __toString(): string
    {
        return $this->base10();
    }

    /**
     * Returns true if the GMP number is a valid PHP int for the platform (32-bit or 64-bit)
     * @return boolean
     */
    public function isInt()
    {
       return gmp_cmp( $this->_gmp, $this->_intMinGmp() ) >= 0 && gmp_cmp( $this->_gmp, $this->_intMaxGmp() ) <= 0 ;
    }

    /**
     * Initialize from an arbitrary length of octets as an unsigned integer.
     */
    public static function fromUnsignedOctets(string $octets): self
    {
        if (!strlen($octets)) {
            throw new \InvalidArgumentException('Empty octets.');
        }
        return new self(gmp_import($octets, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN));
    }

    /**
     * Initialize from an arbitrary length of octets as an signed integer
     * having two's complement encoding.
     */
    public static function fromSignedOctets(string $octets): self
    {
        if (!strlen($octets)) {
            throw new \InvalidArgumentException('Empty octets.');
        }
        $neg = ord($octets[0]) & 0x80;
        // negative, apply inversion of two's complement
        if ($neg) {
            $octets = ~$octets;
        }
        $num = gmp_import($octets, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
        // negative, apply addition of two's complement and produce negative result
        if ($neg) 
        {
            $num = gmp_neg( gmp_add( $num, 1 ) );
        }
        return new self($num);
    }

    /**
     * Get the number as a base 10 integer string.
     */
    public function base10(): string
    {
        if (!isset($this->_num)) {
            $this->_num = gmp_strval($this->_gmp, 10);
        }
        return $this->_num;
    }

    /**
     * Get the number as an integer.
     *
     * @throws \RuntimeException If number overflows integer size
     */
    public function intVal(): int
    {
        if ( ! isset( $this->_intNum ) )
        {
            if ( \gmp_cmp( $this->_gmp, $this->_intMaxGmp() ) > 0)
            {
                throw new \RuntimeException('Integer overflow.');
            }
            if ( \gmp_cmp( $this->_gmp, $this->_intMinGmp() ) < 0 )
            {
                throw new \RuntimeException('Integer underflow.');
            }
            $this->_intNum = gmp_intval( $this->_gmp );
        }
        return $this->_intNum;
    }

    /**
     * Get the number as a `GMP` object.
     *
     * @throws \RuntimeException if number is not a valid integer
     */
    public function gmpObj(): \GMP
    {
        return clone $this->_gmp;
    }

    /**
     * Get the number as an unsigned integer encoded in binary.
     */
    public function unsignedOctets(): string
    {
        return gmp_export($this->_gmp, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
    }

    /**
     * Get the number as a signed integer encoded in two's complement binary.
     */
    public function signedOctets(): string
    {
        switch (gmp_sign($this->_gmp)) {
            case 1:
                return $this->_signedPositiveOctets();
            case -1:
                return $this->_signedNegativeOctets();
        }
        // zero
        return chr(0);
    }

    /**
     * Encode positive integer in two's complement binary.
     */
    private function _signedPositiveOctets(): string
    {
        $bin = gmp_export($this->_gmp, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
        // if first bit is 1, prepend full zero byte to represent positive two's complement
        if (ord($bin[0]) & 0x80) {
            $bin = chr(0x00) . $bin;
        }
        return $bin;
    }

    /**
     * Encode negative integer in two's complement binary.
     */
    private function _signedNegativeOctets(): string
    {
        $num = gmp_abs($this->_gmp);
        // compute number of bytes required
        $width = 1;
        if ($num > 128) {
            $tmp = $num;
            do {
                ++$width;
                $tmp = gmp_div( $tmp, gmp_pow( 2, 8 ) );
                // $tmp >>= 8;
            } while ($tmp > 128);
        }
        // compute two's complement 2^n - x
        $num = gmp_sub( gmp_pow('2', 8 * $width), $num );
        $bin = gmp_export($num, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
        // if first bit is 0, prepend full inverted byte to represent negative two's complement
        if (!(ord($bin[0]) & 0x80)) {
            $bin = chr(0xff) . $bin;
        }
        return $bin;
    }

    /**
     * Get the maximum integer value.
     */
    private function _intMaxGmp(): \GMP
    {
        static $gmp;
        if (!isset($gmp)) {
            $gmp = gmp_init(PHP_INT_MAX, 10);
        }
        return $gmp;
    }

    /**
     * Get the minimum integer value.
     */
    private function _intMinGmp(): \GMP
    {
        static $gmp;
        if (!isset($gmp)) {
            $gmp = gmp_init(PHP_INT_MIN, 10);
        }
        return $gmp;
    }

    /**
     * Converts a BigInteger to a base-10 number.
     *
     * @return string
     */
    public function toString()
    {
        return $this->value->toString();
    }

}
