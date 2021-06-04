<?php

namespace Ocsp\Asn1\Element;

use Ocsp\Asn1\Element;
use Ocsp\Asn1\Encoder;
use Ocsp\Asn1\TaggableElement;
use Ocsp\Asn1\UniversalTagID;

/**
 * ASN.1 element: BIT STRING.
 * 
 * Example:
 * 
 * Example: 
 * The DER encoding of the BIT STRING value "01101110 01011101 11------" which requires 6 padding bits is 03 04 06 6e 5d c0
 *  $b = (new Decoder())->decodeElement( hex2bin('0304066e5dc0' ) );
 *  $e = (new \Ocsp\Asn1\Der\Encoder())->encodeElement( $b );
 *  $h = bin2hex( $e );
 * The result $h is the same as the input.
 * 
 * To store an integer do something like:
 *  $b = BitString::create( trim( pack( 'N', 7232960 ) ), 6 );
 * The pack is trimmed because if the number uses fewer than 4 bytes it will be padded
 */
class BitString extends TaggableElement
{
    /**
     * The bytes containing the value bits.
     *
     * @var string
     */
    private $bytes;

    /**
     * The number of unused bits in the last byte.
     *
     * @var int
     */
    private $numTrailingBits;

    /**
     * Create a new instance.
     *
     * @param string $bytes the bytes containing the value bits
     * @param int $numTrailingBits the number of unused bits in the last byte
     *
     * @return static
     */
    public static function create($bytes, $numTrailingBits)
    {
        $result = new static();

        return $result->setValue($bytes, $numTrailingBits);
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
        return UniversalTagID::BIT_STRING;
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
     * Get the bytes containing the value bits.
     *
     * @return string
     */
    public function getBytes()
    {
        return $this->bytes;
    }

    /**
     * Get the number of unused bits in the last byte.
     *
     * @return int
     */
    public function getNumTrailingBits()
    {
        return $this->numTrailingBits;
    }

    /**
     * Change the value of this BIT STRING.
     *
     * @param string $bytes the bytes containing the value bits
     * @param int $numTrailingBits the number of unused bits in the last byte
     *
     * @return $this
     */
    public function setValue($bytes, $numTrailingBits)
    {
        $this->bytes = (string) $bytes;
        $this->numTrailingBits = (int) $numTrailingBits;

        return $this;
    }

    /**
     * {@inheritdoc}
     *
     * @see \Ocsp\Asn1\Element::getEncodedValue()
     */
    public function getEncodedValue(Encoder $encoder)
    {
        return $encoder->encodeBitString($this->getBytes(), $this->getNumTrailingBits());
    }
}
