<?php

namespace Ocsp\Asn1\Element;

use DateTimeImmutable;
use Ocsp\Asn1\Encoder;
use Ocsp\Asn1\TaggableElement;
use Ocsp\Asn1\TaggableElementTrait;
use Ocsp\Asn1\UniversalTagID;

/**
 * ASN.1 element: INTEGER.
 */
class GeneralizedTime implements TaggableElement
{
    use TaggableElementTrait;

    /**
     * @var \DateTimeImmutable
     */
    private $value;

    /**
     * Create a new instance.
     *
     * @param \DateTimeImmutable $value
     *
     * @return static
     */
    public static function create(DateTimeImmutable $value)
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
        return UniversalTagID::GENERALIZEDTIME;
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
     * @return \DateTimeImmutable
     */
    public function getValue()
    {
        return $this->value;
    }

    /**
     * @param \DateTimeImmutable $value
     *
     * @return $this
     */
    public function setValue(DateTimeImmutable $value)
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
        return $encoder->encodeGeneralizedTime($this->getValue());
    }
}
