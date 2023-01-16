<?php

namespace Ocsp\Asn1\Element;

use Ocsp\Asn1\Encoder;
use Ocsp\Asn1\TaggableElement;
use Ocsp\Asn1\TaggableElementTrait;
use Ocsp\Asn1\UniversalTagID;

/**
 * ASN.1 element: INTEGER.
 */
class Integer implements TaggableElement
{
    use TaggableElementTrait;

    /**
     * @var int|string|\phpseclib\Math\BigInteger|\phpseclib3\Math\BigInteger
     */
    private $value;

    /**
     * Create a new instance.
     *
     * @param int|string|\phpseclib\Math\BigInteger|\phpseclib3\Math\BigInteger $value
     *
     * @return static
     */
    public static function create($value)
    {
        $result = new static();

        return $result->setValue($value);
    }

    /**
     * {@inheritdoc}
     *
     * @see \Ocsp\Asn1\Element::getClass()
     */
    public function getClass()
    {
        return static::CLASS_UNIVERSAL;
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
     * @return int|string|\phpseclib\Math\BigInteger|\phpseclib3\Math\BigInteger
     */
    public function getValue()
    {
        return $this->value;
    }

    /**
     * @param int|string|\phpseclib\Math\BigInteger|\phpseclib3\Math\BigInteger $value
     *
     * @return $this
     */
    public function setValue($value)
    {
        $this->value = $value;

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
