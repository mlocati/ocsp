<?php

namespace Ocsp\Asn1;

use DateTimeImmutable;

/**
 * Interface that all ASN.1 encoders must implement.
 */
interface Encoder
{
    /**
     * Get the handle identifying the encoding.
     */
    public function getEncodingHandle();

    /**
     * Encode an element.
     *
     * @param \Ocsp\Asn1\Element $element
     *
     * @throws \Ocsp\Exception\Asn1EncodingException
     *
     * @return string
     */
    public function encodeElement(Element $element);

    /**
     * Encode the value of an INTEGER element.
     *
     * @param int|string|\phpseclib\Math\BigInteger $value
     *
     * @return string
     */
    public function encodeInteger($value);

    /**
     * Encode the value of an OBJECT IDENTIFIER element.
     *
     * @param string $value
     *
     * @return string
     */
    public function encodeIdentifier($value);

    /**
     * Encode the value of an OCTET STRING identifier.
     *
     * @param string $value
     *
     * @return string
     */
    public function encodeOctetString($value);

    /**
     * Encode the value of a PrintableString element.
     *
     * @param string $value
     *
     * @return string
     */
    public function encodePrintableString($value);

    /**
     * Encode the value of a BIT STRING element.
     *
     * @param string $bytes
     * @param int $unusedBitsInLastByte
     *
     * @return string
     */
    public function encodeBitString($bytes, $unusedBitsInLastByte);

    /**
     * Encode the value of a BIT STRING element.
     *
     * @param \DateTimeImmutable $value
     *
     * @return string
     */
    public function encodeGeneralizedTime(DateTimeImmutable $value);
}
