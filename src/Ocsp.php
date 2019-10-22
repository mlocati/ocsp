<?php

namespace Ocsp;

use Ocsp\Asn1\Der\Decoder as DerDecoder;
use Ocsp\Asn1\Der\Encoder as DerEncoder;
use Ocsp\Asn1\Element;
use Ocsp\Asn1\Element\AbstractList;
use Ocsp\Asn1\Element\GeneralizedTime;
use Ocsp\Asn1\Element\Integer;
use Ocsp\Asn1\Element\ObjectIdentifier;
use Ocsp\Asn1\Element\OctetString;
use Ocsp\Asn1\Element\RawPrimitive;
use Ocsp\Asn1\Element\Sequence;
use Ocsp\Asn1\Tag;
use Ocsp\Asn1\TaggableElement;
use Ocsp\Asn1\UniversalTagID;
use Ocsp\Exception\Asn1DecodingException;
use Ocsp\Exception\ResponseException;

class Ocsp
{
    /**
     * The media type (Content-Type header) to be used when sending the request to the OCSP Responder URL.
     *
     * @var string
     */
    const OCSP_REQUEST_MEDIATYPE = 'application/ocsp-request';

    /**
     * The media type (Content-Type header) that should be included in responses from the OCSP Responder URL.
     *
     * @var string
     */
    const OCSP_RESPONSE_MEDIATYPE = 'application/ocsp-response';

    /**
     * The decoder to be used to decode DER-encoded data.
     *
     * @var \Ocsp\Asn1\Der\Decoder
     */
    private $derDecoder;

    /**
     * The encoder to be used to encode data to DER.
     *
     * @var \Ocsp\Asn1\Der\Encoder
     */
    private $derEncoder;

    /**
     * Initialize the instance.
     */
    public function __construct()
    {
        $this->derDecoder = new DerDecoder();
        $this->derEncoder = new DerEncoder();
    }

    /**
     * Build the raw body to be sent to the OCSP Responder URL with one request.
     *
     * @param \Ocsp\Request $request request to be included in the body
     *
     * @return string
     *
     * @see https://tools.ietf.org/html/rfc6960#section-4.1.1 for OCSPRequest
     */
    public function buildOcspRequestBodySingle(Request $request)
    {
        return $this->buildOcspRequestBody(RequestList::create([$request]));
    }

    /**
     * Build the raw body to be sent to the OCSP Responder URL with a variable number of requests.
     *
     * @param \Ocsp\RequestList $requests the list of requests to be included in the body
     *
     * @return string
     *
     * @see https://tools.ietf.org/html/rfc6960#section-4.1.1 for OCSPRequest
     */
    public function buildOcspRequestBody(RequestList $requests)
    {
        $hashAlgorithm = Sequence::create([
            // OBJECT IDENTIFIER [algorithm]
            ObjectIdentifier::create('1.3.14.3.2.26'), // SHA1
        ]);
        $requestList = new Sequence();
        foreach ($requests->getRequests() as $request) {
            $requestList->addElement(
                // Request
                Sequence::create([
                    // CertID [reqCert]
                    Sequence::create([
                        // AlgorithmIdentifier [hashAlgorithm]
                        $hashAlgorithm,
                        // OCTET STRING [issuerNameHash]
                        OctetString::create(sha1($request->getIssuerNameDer(), true)),
                        // OCTET STRING [issuerKeyHash]
                        OctetString::create(sha1($request->getIssuerPublicKeyBytes(), true)),
                        // CertificateSerialNumber [serialNumber]
                        Integer::create($request->getCertificateSerialNumber()),
                    ]),
                ])
            );
        }

        return $this->derEncoder->encodeElement(
            // OCSPRequest
            Sequence::create([
                // TBSRequest [tbsRequest]
                Sequence::create([
                    $requestList,
                ]),
            ])
        );
    }

    /**
     * Parse the response received from the OCSP Responder when you expect just one certificate revocation status.
     *
     * @param string $rawResponseBody the raw response from the responder
     *
     * @throws \Ocsp\Exception\Asn1DecodingException if $rawBody is not a valid response from the OCSP responder
     * @throws \Ocsp\Exception\ResponseException:: if the request was not successfull
     *
     * @return \Ocsp\Response
     *
     * @see https://tools.ietf.org/html/rfc6960#section-4.2.1
     */
    public function decodeOcspResponseSingle($rawResponseBody)
    {
        $responses = $this->decodeOcspResponse($rawResponseBody)->getResponses();
        if (count($responses) !== 1) {
            throw ResponseException\MultipleResponsesException::create();
        }

        return $responses[0];
    }

    /**
     * Parse the response received from the OCSP Responder when you expect a variable number of certificate revocation statuses.
     *
     * @param string $rawResponseBody the raw response from the responder
     *
     * @throws \Ocsp\Exception\Asn1DecodingException if $rawBody is not a valid response from the OCSP responder
     * @throws \Ocsp\Exception\ResponseException:: if the request was not successfull
     *
     * @return \Ocsp\ResponseList
     *
     * @see https://tools.ietf.org/html/rfc6960#section-4.2.1
     */
    public function decodeOcspResponse($rawResponseBody)
    {
        $ocspResponse = $this->derDecoder->decodeElement($rawResponseBody);
        if (!$ocspResponse instanceof Sequence) {
            throw Asn1DecodingException::create('Invalid response type');
        }
        $this->checkResponseStatus($ocspResponse);
        $responseBytes = $ocspResponse->getFirstChildOfType(0, Element::CLASS_CONTEXTSPECIFIC, Tag::ENVIRONMENT_EXPLICIT);
        if (!$responseBytes instanceof Sequence) {
            throw ResponseException\MissingResponseBytesException::create();
        }

        return $this->decodeResponseBytes($responseBytes);
    }

    /**
     * Check the OCSP response status.
     *
     * @param \Ocsp\Asn1\Element\Sequence $ocspResponse
     *
     * @throws \Ocsp\Exception\ResponseException:: if the request was not successfull
     * @throws \Ocsp\Exception\Asn1DecodingException if the response contains invalid data
     *
     * @see https://tools.ietf.org/html/rfc6960#section-4.2.1
     */
    protected function checkResponseStatus(Sequence $ocspResponse)
    {
        $responseStatus = $ocspResponse->getFirstChildOfType(UniversalTagID::ENUMERATED);
        if ($responseStatus === null) {
            throw Asn1DecodingException::create('Invalid response type');
        }
        switch ($responseStatus->getRawEncodedValue()) {
            case "\x00": // successful (Response has valid confirmations)
                break;
            case "\x01": // malformedRequest (Illegal confirmation request)
                throw ResponseException\MalformedRequestException::create();
            case "\x02": // internalError (Internal error in issuer)
                throw ResponseException\InternalErrorException::create();
            case "\x03": // tryLater (Try again later)
                throw ResponseException\TryLaterException::create();
            case "\x05": // sigRequired (Must sign the request)
                throw ResponseException\SigRequiredException::create();
            case "\x06": // unauthorized (Request unauthorized)
                throw ResponseException\UnauthorizedException::create();
            default:
                throw Asn1DecodingException::create('Invalid response data');
        }
    }

    /**
     * Parse "responseBytes" element of a response received from the OCSP Responder.
     *
     * @param \Ocsp\Asn1\Element\Sequence $responseBytes
     *
     * @throws \Ocsp\Exception\Asn1DecodingException
     * @throws \Ocsp\Exception\ResponseException
     *
     * @see https://tools.ietf.org/html/rfc6960#section-4.2.1
     */
    protected function decodeResponseBytes(Sequence $responseBytes)
    {
        $responseType = $responseBytes->getFirstChildOfType(UniversalTagID::OBJECT_IDENTIFIER);
        $response = $responseBytes->getFirstChildOfType(UniversalTagID::OCTET_STRING);
        if ($responseType !== null && $response !== null) {
            switch ($responseType->getIdentifier()) {
                case '1.3.6.1.5.5.7.48.1.1':
                    return $this->decodeBasicResponse($response->getValue());
            }
        }

        throw ResponseException\MissingResponseBytesException::create();
    }

    /**
     * Parse the "responseBytes" element of a response received from the OCSP Responder.
     *
     * @param string $responseBytes
     *
     * @throws \Ocsp\Exception\Asn1DecodingException
     * @throws \Ocsp\Exception\ResponseException
     *
     * @see https://tools.ietf.org/html/rfc6960#section-4.2.1
     *
     * @return \Ocsp\ResponseList
     */
    protected function decodeBasicResponse($responseBytes)
    {
        $basicOCSPResponse = $this->derDecoder->decodeElement($responseBytes);
        if (!$basicOCSPResponse instanceof Sequence) {
            throw Asn1DecodingException::create();
        }
        $tbsResponseData = $basicOCSPResponse->getFirstChildOfType(UniversalTagID::SEQUENCE);
        if (!$tbsResponseData instanceof Sequence) {
            throw Asn1DecodingException::create();
        }
        $responses = $tbsResponseData->getFirstChildOfType(UniversalTagID::SEQUENCE);
        if (!$responses instanceof Sequence) {
            throw Asn1DecodingException::create();
        }
        $responseList = ResponseList::create();
        foreach ($responses->getElements() as $singleResponse) {
            if ($singleResponse instanceof Sequence && $singleResponse->getTag() === null) {
                $responseList->addResponse($this->decodeBasicSingleResponse($singleResponse));
            }
        }
        if ($responseList->getResponses() === []) {
            throw ResponseException\MissingResponseBytesException::create();
        }

        return $responseList;
    }

    /**
     * Parse a "SingleResponse" element of a BasicOCSPResponse.
     *
     * @param \Ocsp\Asn1\Element\Sequence $singleResponse
     *
     * @throws \Ocsp\Exception\Asn1DecodingException
     * @throws \Ocsp\Exception\ResponseException
     *
     * @return \Ocsp\Response
     *
     * @see https://tools.ietf.org/html/rfc6960#section-4.2.1
     */
    protected function decodeBasicSingleResponse(Sequence $singleResponse)
    {
        $elements = $singleResponse->getElements();
        $certID = isset($elements[0]) ? $elements[0] : null;
        if (!$certID instanceof Sequence) {
            throw Asn1DecodingException::create();
        }
        $certificateSerialNumber = (string) $certID->getFirstChildOfType(UniversalTagID::INTEGER, Element::CLASS_UNIVERSAL)->getValue();
        $thisUpdate = $singleResponse->getFirstChildOfType(UniversalTagID::GENERALIZEDTIME, Element::CLASS_UNIVERSAL)->getValue();
        $certStatus = isset($elements[1]) ? $elements[1] : null;
        if ($certStatus === null) {
            throw Asn1DecodingException::create();
        }
        $certStatusTag = $certStatus instanceof TaggableElement ? $certStatus->getTag() : null;
        if ($certStatusTag === null) {
            if ($certStatus->getClass() !== Element::CLASS_CONTEXTSPECIFIC) {
                throw Asn1DecodingException::create();
            }
            $tagID = $certStatus->getTypeID();
        } else {
            if ($certStatusTag->getClass() !== Element::CLASS_CONTEXTSPECIFIC) {
                throw Asn1DecodingException::create();
            }
            $tagID = $certStatusTag->getTagID();
        }
        switch ($tagID) {
            case 0:
                return Response::good($thisUpdate, $certificateSerialNumber);
            case 1:
                $revokedOn = null;
                $revocationReason = Response::REVOCATIONREASON_UNSPECIFIED;
                if ($certStatus instanceof GeneralizedTime) {
                    $revokedOn = $certStatus->getValue();
                } elseif ($certStatus instanceof AbstractList) {
                    $certStatusChildren = $certStatus->getElements();
                    if (isset($certStatusChildren[0]) && $certStatusChildren[0] instanceof GeneralizedTime) {
                        $revokedOn = $certStatusChildren[0]->getValue();
                        if (isset($certStatusChildren[1]) && $certStatusChildren[1] instanceof RawPrimitive) {
                            $bitString = $certStatusChildren[1]->getRawEncodedValue();
                            if (strlen($bitString) === 1) {
                                $revocationReason = ord($bitString[0]);
                            }
                        }
                    }
                }
                if ($revokedOn === null) {
                    throw Asn1DecodingException::create('Failed to find the revocation date/time');
                }

                return Response::revoked($thisUpdate, $certificateSerialNumber, $revokedOn, $revocationReason);
            case 2:
            default:
                return Response::unknown($thisUpdate, $certificateSerialNumber);
        }
    }
}
