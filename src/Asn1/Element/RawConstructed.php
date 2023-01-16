<?php

namespace Ocsp\Asn1\Element;

use Ocsp\Asn1\TaggableElementTrait;

/**
 * An un-decoded ASN.1 CONSTRUCTED element.
 */
class RawConstructed extends AbstractList
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
     * @var int|string|\phpseclib\Math\BigInteger|\phpseclib3\Math\BigInteger
     */
    private $typeID;

    /**
     * The class (the value of one of the Element::CLASS_... constants).
     *
     * @var string
     */
    private $class;

    /**
     * Create a new instance.
     *
     * @param string $encoding the handle of the encoding
     * @param int|string|\phpseclib\Math\BigInteger|\phpseclib3\Math\BigInteger $typeID
     * @param string $class the class (the value of one of the Element::CLASS_... constants)
     * @param \Ocsp\Asn1\Element[] $elements
     *
     * @return static
     */
    public static function create($encoding, $typeID, $class, array $elements = [])
    {
        $result = new static();
        $result->encoding = $encoding;
        $result->typeID = $typeID;
        $result->class = $class;

        return $result->addElements($elements);
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
        return true;
    }
}
