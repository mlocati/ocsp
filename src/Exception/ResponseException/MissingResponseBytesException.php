<?php

namespace Ocsp\Exception\ResponseException;

use Ocsp\Exception\ResponseException;

/**
 * Exception thrown when the response does not contain any revocation-related data.
 */
class MissingResponseBytesException extends ResponseException
{
    /**
     * Create a new instance.
     *
     * @return static
     */
    public static function create()
    {
        return new static('Response does not contain revocation data');
    }
}
