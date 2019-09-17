<?php

namespace Ocsp\Exception;

/**
 * Exception thrown when decoding an encoded ASN.1 (probably because it's malformed).
 */
class Asn1DecodingException extends Exception
{
    /**
     * Create a new instance.
     *
     * @param string $message
     *
     * @return static
     */
    public static function create($message = '')
    {
        $message = (string) $message;
        if ($message === '') {
            $message = 'Problems decoding to ASN.1';
        }

        return new static($message);
    }
}
