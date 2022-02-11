<?php

namespace Ocsp\Asn1\Element;

use Ocsp\Asn1\Encoder;
use Ocsp\Asn1\TaggableElement;
use Ocsp\Asn1\TaggableElementTrait;
use Ocsp\Exception\Asn1EncodingException;

/**
 * An un-decoded ASN.1 PRIMITIVE element.
 */
class RawPrimitive implements TaggableElement
{
    use TaggableElementTrait;

    /**
     * The handle of the encoding.
     *
     * @var string
     */
    private $encoding;

    /**
     * The decoded type ID.
     *
     * @var int|string|\Ocsp\BigInteger
     */
    private $typeID;

    /**
     * The class (the value of one of the Element::CLASS_... constants).
     *
     * @var string
     */
    private $class;

    /**
     * The not decoded bytes representing the value.
     *
     * @var string
     */
    private $rawEncodedValue;

    /**
     * Create a new instance.
     *
     * @param string $encoding the handle of the encoding
     * @param int|string|\Ocsp\BigInteger $typeID
     * @param string $class the class (the value of one of the Element::CLASS_... constants)
     * @param string $rawEncodedValue the not decoded bytes representing the value
     *
     * @return static
     */
    public static function create($encoding, $typeID, $class, $rawEncodedValue)
    {
        $result = new static();
        $result->encoding = $encoding;
        $result->typeID = $typeID;
        $result->class = $class;
        $result->rawEncodedValue = $rawEncodedValue;

        return $result;
    }

    /**
     * {@inheritdoc}
     *
     * @see \Ocsp\Asn1\Element::getClass()
     */
    public function getClass()
    {
        return $this->class;
    }

    /**
     * {@inheritdoc}
     *
     * @see \Ocsp\Asn1\Element::getTypeID()
     */
    public function getTypeID()
    {
        return $this->typeID;
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
     * Get the not decoded bytes representing the value.
     *
     * @return string
     */
    public function getRawEncodedValue()
    {
        return $this->rawEncodedValue;
    }

    /**
     * {@inheritdoc}
     *
     * @see \Ocsp\Asn1\Element::getEncodedValue()
     */
    public function getEncodedValue(Encoder $encoder)
    {
        if ($encoder->getEncodingHandle() === $this->encoding) {
            return $this->rawEncodedValue;
        }
        throw Asn1EncodingException::create('Unable to decode/encode an ASN.1 element');
    }
}
