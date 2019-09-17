<?php

namespace Ocsp;

/**
 * List of requests to be sent to the OCSP Responder url.
 */
class RequestList
{
    /**
     * @var \Ocsp\Request[]
     */
    private $requests = [];

    /**
     * Create a new instance.
     *
     * @param \Ocsp\Request[] $requests
     *
     * @return static
     */
    public static function create(array $requests = [])
    {
        $result = new static();

        return $result->addRequests($requests);
    }

    /**
     * Add a new request to this list.
     *
     * @param \Ocsp\Request $request
     *
     * @return $this
     */
    public function addRequest(Request $request)
    {
        $this->requests[] = $request;

        return $this;
    }

    /**
     * Add new requests to this list.
     *
     * @param \Ocsp\Request[] $requests
     *
     * @return $this
     */
    public function addRequests(array $requests)
    {
        foreach ($requests as $request) {
            $this->addRequest($request);
        }

        return $this;
    }

    /**
     * Get the request list.
     *
     * @return \Ocsp\Request[]
     */
    public function getRequests()
    {
        return $this->requests;
    }
}
