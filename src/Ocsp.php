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
    const ERR_SUCCESS = 0;
    const ERR_MALFORMED_ASN1 = 1;
    const ERR_INTERNAL_ERROR = 2;
    const ERR_TRY_LATER = 3;
    const ERR_SIG_REQUIRED = 5;
    const ERR_UNAUTHORIZED = 6;
    const ERR_UNSUPPORTED_VERSION = 12;
    const ERR_REQLIST_EMPTY = 13;
    const ERR_REQLIST_MULTI = 14;
    const ERR_UNSUPPORTED_EXT = 15;
    const ERR_UNSUPPORTED_ALG = 16;
    
    const CERT_STATUS_GOOD = 0;
    const CERT_STATUS_REVOKED = 1;
    const CERT_STATUS_UNKNOWN = 2;
    
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
                        Integer::create( Integer::decodeInteger( $request->getCertificateSerialNumber() ) ),
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
     * @param string $signer The certificate used to sign the parts of the response (the issuer certificate)
     *
     * @throws \Ocsp\Exception\Asn1DecodingException if $rawBody is not a valid response from the OCSP responder
     * @throws \Ocsp\Exception\ResponseException:: if the request was not successfull
     *
     * @return \Ocsp\Response
     *
     * @see https://tools.ietf.org/html/rfc6960#section-4.2.1
     */
    public function decodeOcspResponseSingle( $rawResponseBody, $signer = null )
    {
        $responses = $this->decodeOcspResponse( $rawResponseBody, $signer )->getResponses();
        if (count($responses) !== 1) {
            throw ResponseException\MultipleResponsesException::create();
        }

        return $responses[0];
    }

    /**
     * Parse the response received from the OCSP Responder when you expect a variable number of certificate revocation statuses.
     *
     * @param string $rawResponseBody the raw response from the responder
     * @param string $signer The certificate used to sign the parts of the response (the issuer certificate)
     *
     * @throws \Ocsp\Exception\Asn1DecodingException if $rawBody is not a valid response from the OCSP responder
     * @throws \Ocsp\Exception\ResponseException:: if the request was not successfull
     *
     * @return \Ocsp\ResponseList
     *
     * @see https://tools.ietf.org/html/rfc6960#section-4.2.1
     */
    public function decodeOcspResponse( $rawResponseBody, $signer = null )
    {
        $ocspResponse = $this->derDecoder->decodeElement($rawResponseBody);
        if (!$ocspResponse instanceof Sequence)
        {
            throw Asn1DecodingException::create('Invalid response type');
        }

        $this->checkResponseStatus( $ocspResponse );

        $responseBytes = \Ocsp\Asn1\asSequence( $ocspResponse->getFirstChildOfType( 0, Element::CLASS_CONTEXTSPECIFIC, Tag::ENVIRONMENT_EXPLICIT ) );
        if ( ! $responseBytes )
        {
            throw ResponseException\MissingResponseBytesException::create();
        }

        return $this->decodeResponseBytes( $responseBytes, $signer );
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
        $responseStatus = \Ocsp\Asn1\asEnumerated( $ocspResponse->getFirstChildOfType(UniversalTagID::ENUMERATED) );
        if ($responseStatus === null) {
            throw Asn1DecodingException::create('Invalid response type');
        }
        switch ( $responseStatus->getValue() ) 
        {
            case self::ERR_SUCCESS:        // successful (Response has valid confirmations)
                break;
            case self::ERR_MALFORMED_ASN1: // malformedRequest (Illegal confirmation request)
                throw ResponseException\MalformedRequestException::create();
            case self::ERR_INTERNAL_ERROR: // internalError (Internal error in issuer)
                throw ResponseException\InternalErrorException::create();
            case self::ERR_TRY_LATER:      // tryLater (Try again later)
                throw ResponseException\TryLaterException::create();
            case self::ERR_SIG_REQUIRED:   // sigRequired (Must sign the request)
                throw ResponseException\SigRequiredException::create();
            case self::ERR_UNAUTHORIZED  : // unauthorized (Request unauthorized)
                throw ResponseException\UnauthorizedException::create();
            default:
                throw Asn1DecodingException::create('Invalid response data');
        }
    }

    /**
     * Parse "responseBytes" element of a response received from the OCSP Responder.
     *
     * @param \Ocsp\Asn1\Element\Sequence $responseBytes
     * @param string $signer The certificate used to sign the parts of the response (the issuer certificate)
     *
     * @throws \Ocsp\Exception\Asn1DecodingException
     * @throws \Ocsp\Exception\ResponseException
     *
     * @see https://tools.ietf.org/html/rfc6960#section-4.2.1
     */
    protected function decodeResponseBytes( $responseBytes, $signer = null )
    {
        $responseType = \Ocsp\Asn1\asObjectIdentifier( $responseBytes->getFirstChildOfType(UniversalTagID::OBJECT_IDENTIFIER) );
        if ( $responseType )
        {
            $response = \Ocsp\Asn1\asOctetString( $responseBytes->getFirstChildOfType(UniversalTagID::OCTET_STRING) );
            if ( $response !== null )
            {
                switch ( $responseType->getIdentifier() )
    {
                case '1.3.6.1.5.5.7.48.1.1':
                        return $this->decodeBasicResponse( $response->getValue(), $signer );
                }
            }
        }

        throw ResponseException\MissingResponseBytesException::create();
    }

    /**
     * Parse the "responseBytes" element of a response received from the OCSP Responder.
     *
     * @param string $responseBytes
     * @param string $signer The certificate used to sign the parts of the response (the issuer certificate)
     *
     * @see https://tools.ietf.org/html/rfc6960#section-4.2.1
     *
     * @return \Ocsp\ResponseList
     */
    protected function decodeBasicResponse( $responseBytes, $signer = null )
    {
        /*
            OCSPResponse ::= SEQUENCE 
            {
                responseStatus         OCSPResponseStatus,
                responseBytes          [0] EXPLICIT ResponseBytes OPTIONAL 
            }

            ResponseBytes ::=       SEQUENCE
            {
                responseType   OBJECT IDENTIFIER,
                response       OCTET STRING
            }

            responseType will be id-pkix-ocsp-basic (1.3.6.1.5.5.7.48.1.1)
            reponse will be an encoded BasicOCSPResponse

            BasicOCSPResponse ::= SEQUENCE
            {
                tbsResponseData     ResponseData,
                signatureAlgorithm  AlgorithmIdentifier,
                signature           BIT STRING,
                certs               [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL 
            }

            ResponseData ::= SEQUENCE
            {
                version             [0] EXPLICIT Version DEFAULT v1,
                responderID             ResponderID,
                producedAt              GeneralizedTime,
                responses               SEQUENCE OF SingleResponse,
                responseExtensions  [1] EXPLICIT Extensions OPTIONAL
            }

            ResponderID ::= CHOICE
            {
                byName               [1] Name,
                byKey                [2] KeyHash
            }

            KeyHash ::= OCTET STRING -- SHA-1 hash of the value of the BIT STRING subjectPublicKey [excluding the tag, length, and number of unused bits] in the responder's certificate

            SingleResponse ::= SEQUENCE
            {
                certID                       CertID,
                certStatus                   CertStatus,
                thisUpdate                   GeneralizedTime,
                nextUpdate          [0]      EXPLICIT GeneralizedTime OPTIONAL,
                singleExtensions    [1]      EXPLICIT Extensions OPTIONAL
            }

            CertID ::= SEQUENCE
            {
                hashAlgorithm       AlgorithmIdentifier,
                issuerNameHash      OCTET STRING, -- Hash of issuer's DN
                issuerKeyHash       OCTET STRING, -- Hash of issuer's public key
                serialNumber        CertificateSerialNumber
            }

            CertStatus ::= CHOICE
            {
                good        [0]     IMPLICIT NULL,
                revoked     [1]     IMPLICIT RevokedInfo,
                unknown     [2]     IMPLICIT UnknownInfo
            }

            RevokedInfo ::= SEQUENCE
            {
                revocationTime              GeneralizedTime,
                revocationReason    [0]     EXPLICIT CRLReason OPTIONAL
            }

            UnknownInfo ::= NULL
         */

        $basicOCSPResponse = \Ocsp\Asn1\asSequence( $this->derDecoder->decodeElement( $responseBytes ) );
        if ( ! $basicOCSPResponse )
    {
            throw Asn1DecodingException::create();
        }

        $tbsResponseData = \Ocsp\Asn1\asSequence( $basicOCSPResponse->getFirstChildOfType(UniversalTagID::SEQUENCE ) );
        if ( ! $tbsResponseData ) 
        {
            throw Asn1DecodingException::create();
        }

        $signers = $this->verifySigning( $basicOCSPResponse, $signer, $this->derEncoder->encodeElement( $tbsResponseData ) );
        if ( $signer && ! $signers )
        {
            throw new ResponseException( 'The response is signed but the signature cannot be verified' );
        }
    
        $responses = \Ocsp\Asn1\asSequence( $tbsResponseData->getFirstChildOfType( UniversalTagID::SEQUENCE ) );
        if (!$responses instanceof Sequence) {
            throw Asn1DecodingException::create();
        }

        $responseList = ResponseList::create();
        foreach ($responses->getElements() as $singleResponse)
        {
            if ($singleResponse instanceof Sequence && $singleResponse->getTag() === null) {
                $responseList->addResponse($this->decodeBasicSingleResponse($singleResponse));
            }
        }

        if ( $responseList->getResponses() === [] )
        {
            throw ResponseException\MissingResponseBytesException::create();
        }

        return $responseList;
    }

    /**
	 * Convert binary (DER) ASN.1 string to PEM format.  The data is
	 * base64-encoded and wrapped in a header ('-----BEGIN
	 * $type-----') and a footer ('-----END $type-----').  The
	 * conversion is required by PHP openssl_* functions for
	 * key-containing parameters.
	 *
	 * @param string $data DER-encode binary data
	 * @param string $type object type (i. e. 'CERTIFICATE', 'RSA
	 * PUBLIC KEY', etc.
	 *
	 * @return string data in PEM format
	 */
    private static function PEMize( $data, $type )
	{
		return "-----BEGIN $type-----\r\n"
		. chunk_split(base64_encode($data))
		. "-----END $type-----\r\n";
	}

	/** @name Signature Verification
	 *
	 * Methods related to signature verification.  When called on those subclasses
	 * of PKI2X\Message which describe signatureless messages.
	 */
	private static function _verifySig($data, $signature, $cert, $hashAlg)
	{
		$c = $cert;
		if (strpos($cert, '-----BEGIN CERTIFICATE-----') !== 0) {
			$c = self::PEMize($cert, 'CERTIFICATE');
		}

        // file_put_contents('c:/requester.txt',
		// 	chunk_split( base64_encode( $data ) ) . "\n\n" .
		// 	chunk_split( base64_encode( $signature ) ) . "\n\n" . 
		// 	$hashAlg . "\n\n" .
        //     $c 
		// );

		return openssl_verify($data, $signature, $c, $hashAlg);
	}

    /**
     * Look for signature information in a sequence and if it exists verify the signing
     *
     * @param Sequence $sequence
     * @param string $signer The certificate used to sign the parts of the response (the issuer certificate)
     * @param string $signedData;
     * @return boolean
     */
    public static function verifySigning( $sequence, $cert, $signedData )
    {
        // If there is a signature the sequence will have > 1 element otherwise return true
        if ( count( $sequence->getElements() ) <= 1 ) return true;

		$signature = self::getSignatureRaw( $sequence );
		$signers = array();

		$ha = self::getSignatureAlgorithm( $sequence );
		$hashAlg = \Ocsp\Asn1\OID2Name[ $ha ];
		if ( ! isset( $hashAlg ) )
		{
			throw new \Exception("Unsupported signature algorithm $ha");
		}

		$certs = self::getSignerCerts( $sequence );
		if ( isset( $cert ) )
		{
			$certs = array( $cert );
		}

        // If there are no certificates there can be no valid verification
        // This is not an error.  If the responder did not include a certificate and
        // the caller did not supply the responder's then no verification is possible.

		foreach( $certs as $cert )
		{
			$ret = self::_verifySig( $signedData, $signature, $cert, $hashAlg );
			if ( $ret === 1 )
			{
				array_push( $signers, $cert );
			}
		}
		return $signers;
    }

    /**
     * Access any certificates provided
     *
     * @param Sequence $sequence
     * @return string[]
     */
	private static function getSignerCerts( $sequence )
	{
        $signerCerts = array();
        $certs = \Ocsp\Asn1\asSequence( $sequence->at(4) );
        foreach( $certs ? $certs->getElements() : array() as $certSequence )
        {
            array_push( $signerCerts, (new DerEncoder)->encodeElement( $certSequence ) );
        }

		return $signerCerts;
	}

    /**
     * Get the algorithm from the signed sequence
     *
     * @param Sequence $sequence
     * @return string
     */
	private static function getSignatureAlgorithm( $sequence )
	{
		// skip tbsResponseData 
		$sigalgOID = \Ocsp\Asn1\asObjectIdentifier( $sequence->at( 2 )->asSequence()->first() );
        return $sigalgOID 
            ? $sigalgOID->getIdentifier() /* signatureAlgorithm */
            : null;
	}

    /**
     * Get the signature bits
     *
     * @param Sequence $sequence
     * @param bool $stripUnusedBitsFlag (default false)
     * @return string
     */
	private static function getSignatureRaw( $sequence, $stripUnusedBitsFlag = false )
	{
		$sig = \Ocsp\Asn1\asBitString( $sequence->getFirstChildOfType( UniversalTagID::BIT_STRING ) )->getBytes();
        return $stripUnusedBitsFlag 
            ? substr( $sig, 1 ) /* skip the "unused bits" octet */
            : $sig;
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
        /** @var Integer */
        $integer = $certID->getFirstChildOfType(UniversalTagID::INTEGER, Element::CLASS_UNIVERSAL);
        $certificateSerialNumber = (string) $integer->getValue();
        /** @var GeneralizedTime */
        $genTime = $singleResponse->getFirstChildOfType(UniversalTagID::GENERALIZEDTIME, Element::CLASS_UNIVERSAL);
        $thisUpdate = $genTime->getValue();
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
                    /** @var Integer[] */
                    $certStatusChildren = $certStatus->getElements();
                    if (isset($certStatusChildren[0]) && $certStatusChildren[0] instanceof GeneralizedTime) {
                        $revokedOn = $certStatusChildren[0]->getValue();
                        if (isset($certStatusChildren[1]) && $certStatusChildren[1] instanceof RawPrimitive) {
                            /** @var RawPrimitive[] $certStatusChildren */
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
