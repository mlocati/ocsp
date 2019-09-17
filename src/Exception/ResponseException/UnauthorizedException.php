<?php

namespace Ocsp\Exception\ResponseException;

use Ocsp\Exception\ResponseException;

/**
 * Exception thrown when the response from the OCSP is "unauthorized".
 */
class UnauthorizedException extends ResponseException
{
    /**
     * Create a new instance.
     *
     * @return static
     */
    public static function create()
    {
        return new static('Request unauthorized');
    }
}
