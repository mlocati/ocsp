<?php

namespace Ocsp\Asn1;

/**
 * Interface that all ASN.1 decoders must implement.
 */
interface Decoder
{
    /**
     * Get the handle identifying the encoding.
     */
    public function getEncodingHandle();

    /**
     * Decode an ASN.1 element starting from its bytes.
     *
     * @param string $bytes
     *
     * @throws \Ocsp\Exception\Asn1DecodingException
     *
     * @return \Ocsp\Asn1\Element
     */
    public function decodeElement($bytes);
}
