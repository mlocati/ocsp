<?php

namespace Ocsp\Exception\ResponseException;

use Ocsp\Exception\ResponseException;

/**
 * Exception thrown when we expect just one response from the OCSP Responder, but we received more that one.
 */
class MultipleResponsesException extends ResponseException
{
    /**
     * Create a new instance.
     *
     * @return static
     */
    public static function create()
    {
        return new static('Multiple OCSP responses received');
    }
}
