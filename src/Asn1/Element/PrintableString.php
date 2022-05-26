<?php

namespace Ocsp\Asn1\Element;

use Ocsp\Asn1\Encoder;
use Ocsp\Asn1\TaggableElement;
use Ocsp\Asn1\TaggableElementTrait;
use Ocsp\Asn1\UniversalTagID;
use Ocsp\Exception\InvalidAsn1Value;

/**
 * ASN.1 element: PrintableString.
 */
class PrintableString implements TaggableElement
{
    use TaggableElementTrait;

    /**
     * The value of the element.
     *
     * @var string
     */
    private $value;

    /**
     * Create a new instance.
     *
     * @param string $value the value of the element
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
        return UniversalTagID::PRINTABLESTRING;
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
     * Get the value of the element.
     *
     * @return string
     */
    public function getValue()
    {
        return $this->value;
    }

    /**
     * Update the value of the element.
     *
     * @param string $value
     *
     * @throws \Ocsp\Exception\InvalidAsn1Value
     *
     * @return $this
     */
    public function setValue($value)
    {
        $value = (string) $value;
        if (!preg_match('/^[A-Za-z0-9 &\'()+,\-.\/:=?]*$/', $value)) {
            throw InvalidAsn1Value::create('Invalid ASN.1 PrintableString value');
        }
        $this->value = (string) $value;

        return $this;
    }

    /**
     * {@inheritdoc}
     *
     * @see \Ocsp\Asn1\Element::getEncodedValue()
     */
    public function getEncodedValue(Encoder $encoder)
    {
        return $encoder->encodePrintableString($this->getValue());
    }
}
