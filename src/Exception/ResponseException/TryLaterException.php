<?php

namespace Ocsp\Exception\ResponseException;

use Ocsp\Exception\ResponseException;

/**
 * Exception thrown when the response from the OCSP is "tryLater".
 */
class TryLaterException extends ResponseException
{
    /**
     * Create a new instance.
     *
     * @return static
     */
    public static function create()
    {
        return new static('Try again later');
    }
}
