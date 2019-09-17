<?php

namespace Ocsp\Exception;

/**
 * Exception thrown when encoding from ASN.1 (probably because of wrong parameters).
 */
class Asn1EncodingException extends Exception
{
    /**
     * Create a new instance.
     *
     * @param string $message
     *
     * @return static
     */
    public static function create($message)
    {
        return new static($message);
    }
}
