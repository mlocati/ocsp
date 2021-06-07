<?php

namespace Ocsp\Asn1\Element;

use Ocsp\Asn1\Element;
use Ocsp\Asn1\Util\BigInteger;
use Ocsp\Asn1\Encoder;
use Ocsp\Asn1\TaggableElement;
use Ocsp\Asn1\UniversalTagID;

/**
 * ASN.1 element: INTEGER.
 */
class Integer extends TaggableElement
{
    /**
     * @var int|string|BigInteger
     */
    private $value;

    /**
     * Create a new instance.
     *
     * @param int|string|BigInteger $value
     *
     * @return static
     */
    public static function create( $value )
    {
        $result = new static();

        return $result->setValue( $value );
    }

    /**
     * Decode the value of an INTEGER element.
     *
     * @param string $bytes
     *
     * @return int|BigInteger
     */
    public static function decodeInteger( $bytes )
    {
        $bint = $bytes instanceof BigInteger
            ? $bytes
            : new BigInteger( $bytes );

        return $bint->isInt()
            ? (int)$bint->intVal()
            : $bint;

    }

    /**
     * {@inheritdoc}
     *
     * @see \Ocsp\Asn1\Element::getClass()
     */
    public function getClass()
    {
        return Element::CLASS_UNIVERSAL;
    }

    /**
     * {@inheritdoc}
     *
     * @see \Ocsp\Asn1\Element::getTypeID()
     */
    public function getTypeID()
    {
        return UniversalTagID::INTEGER;
    }

    /**
     * {@inheritdoc}
     *
     * @see \Ocsp\Asn1\Element::isConstructed()
     */
    public function isConstructed()
    {
        return false;
    }

    /**
     * @return int|string|BigInteger
     */
    public function getValue()
    {
        return $this->value;
    }

    /**
     * @param BigInteger|int|string $value
     *
     * @return $this
     */
    public function setValue($value)
    {
        if ( is_int( $value ) || $value instanceof BigInteger )
        $this->value = $value;
        else if ( $value instanceof \GMP )
            $this->value = new BigInteger( $value );
        else if ( filter_var( $value, FILTER_VALIDATE_INT ) )
            $this->value = (int)$value;
        else
            $this->value = new BigInteger( \gmp_init( $value ) );

        return $this;
    }

    /**
     * {@inheritdoc}
     *
     * @see \Ocsp\Asn1\Element::getEncodedValue()
     */
    public function getEncodedValue(Encoder $encoder)
    {
        return $encoder->encodeInteger($this->getValue());
    }
}
