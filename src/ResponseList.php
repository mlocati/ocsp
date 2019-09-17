<?php

namespace Ocsp;

/**
 * List of responses received from the OCSP Responder.
 */
class ResponseList
{
    /**
     * @var \Ocsp\Response[]
     */
    private $responses = [];

    /**
     * Create a new instance.
     *
     * @param \Ocsp\Response[] $responses
     *
     * @return static
     */
    public static function create(array $responses = [])
    {
        $result = new static();

        return $result->addResponses($responses);
    }

    /**
     * Add a new response to this list.
     *
     * @param \Ocsp\Response $response
     *
     * @return $this
     */
    public function addResponse(Response $response)
    {
        $this->responses[] = $response;

        return $this;
    }

    /**
     * Add new responses to this list.
     *
     * @param \Ocsp\Response[] $responses
     *
     * @return $this
     */
    public function addResponses(array $responses)
    {
        foreach ($responses as $response) {
            $this->addResponse($response);
        }

        return $this;
    }

    /**
     * Get the response list.
     *
     * @return \Ocsp\Response[]
     */
    public function getResponses()
    {
        return $this->responses;
    }
}
