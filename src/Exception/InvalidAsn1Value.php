<?php

namespace Ocsp\Exception;

/**
 * Exception thrown when trying to set an invalid value for an ASN.1 element.
 */
class InvalidAsn1Value extends Exception
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
