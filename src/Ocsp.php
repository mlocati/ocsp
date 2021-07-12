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

use function Ocsp\Asn1\asObjectIdentifier;
use function Ocsp\Asn1\asOctetString;
use function Ocsp\Asn1\asSequence;

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

    /** Conversion from OID to algorithm names recognized by openssl_*
     *    functions.
     */
    const OID2Name = array( /* Signatures */
        '1.2.840.10040.4.3' => 'DSA-SHA1', /* id-dsa-with-sha1 */
        '1.2.840.113549.1.1.1' => 'RSA', /* rsaEncryption */
        '1.2.840.113549.1.1.4' => 'RSA-MD5', /* md5WithRSAEncryption */
        '1.2.840.113549.1.1.5' => 'RSA-SHA1', /* sha1WithRSAEncryption */
        '1.2.840.113549.1.1.11' => 'SHA256', /* sha256WithRSAEncryption */
        '1.2.840.113549.1.1.12' => 'SHA384', /* sha384WithRSAEncryption */
        '1.2.840.113549.1.1.13' => 'SHA512', /* sha512WithRSAEncryption */
        '1.2.840.113549.1.1.14' => 'SHA224', /* sha224WithRSAEncryption */
        /* Digests */
        '2.16.840.1.101.3.4.2.1' => 'SHA256',
        '2.16.840.1.101.3.4.2.2' => 'SHA384',
        '2.16.840.1.101.3.4.2.3' => 'SHA512',
        '2.16.840.1.101.3.4.2.4' => 'SHA224',
        '1.3.14.3.2.26' => 'SHA1',
        '1.2.840.113549.2.5' => 'MD5',
        /* DN components */
        '1.2.840.113549.1.9.1' => ''
    );

    const id_pkix_ocsp_basic = '1.3.6.1.5.5.7.48.1.1';
    const authorityInfoAccess = '1.3.6.1.5.5.7.1.1';
    const caIssuers = '1.3.6.1.5.5.7.48.2';
    const sha256WithRSAEncryption = '1.2.840.113549.1.1.11';

    /**
     * Parse the certificate to find the OCSP responder Url and the issuer certificate
     * @param string $path
     * @return string[]
     */
    static function getCertificateFromFile( $path )
    {
        $certificateLoader = new \Ocsp\CertificateLoader();
        $certificate = $certificate = $certificateLoader->fromFile( $path );

        return self::getCertificate( $certificate );
    }

    /**
     * Parse the certificate to find the OCSP responder Url and the issuer certificate
     * @param Sequence $certificate
     * @return string[]
     */
    static function getCertificate( $certificate, $issuerCertificate = null )
    {
        $result = array();

        $result['cert'] = $certificate;
        $result['certificateInfo'] = $certificateInfo = new \Ocsp\CertificateInfo();
        $urlOfIssuerCertificate = $certificateInfo->extractIssuerCertificateUrl( $certificate );
        $result['ocspResponderUrl'] = $certificateInfo->extractOcspResponderUrl( $certificate );
        $result['issuerBytes'] = $issuerBytes = $issuerCertificate ? (new DerEncoder())->encodeElement( $issuerCertificate ) : file_get_contents( $urlOfIssuerCertificate );
        $certificateLoader = new \Ocsp\CertificateLoader();
        $result['issuerCertificate'] = $issuerCertificate ? $issuerCertificate : $certificateLoader->fromString( $issuerBytes );
        return $result;
    }

    /**
     * Checks that the subject certificate is signed by the issuer certificate
     *
     * @param Sequence $subjectCertificate
     * @param Sequence $issuerCertificate If the issuer certificate is not provided it will be retrieve on the path found in the subject certificate
     * @return bool
     * @throws \Exception If there is a problem validating the certificate
     */
    static function validateCertificate( Sequence $subjectCertificate, Sequence $issuerCertificate = null )
    {
        $certificateInfo = new \Ocsp\CertificateInfo();
        if ( $issuerCertificate )
        {
            // Convert the Sequence to a PEM so the OpenSSL function will use it
            $issuerCertificate = self::PEMize( (new DerEncoder())->encodeElement( $issuerCertificate) );
        }
        else
        {
            $issuerUrl = $certificateInfo->extractIssuerCertificateUrl( $subjectCertificate );
            if ( ! $issuerUrl )
                throw new \Exception('The issuer certificate has not been provided and a url to the certificate is not in the subject certificate');

            if ( ! openssl_x509_export( file_get_contents( $issuerUrl ), $issuerCertificate ) )
                throw new \Exception( sprintf( 'Unable to access the issuer certificate at the supplied location: \'%s\'', $issuerUrl ) );
            // $issuerCertificate = self::PEMize( self::pem2der( file_get_contents( $issuerUrl ) ) );
        }

        // Get the subject's signature
        $signatureBytes = $certificateInfo->getSignatureBytes( $subjectCertificate );
        if ( ! $signatureBytes )
            throw new \Exception('Unable to retrieve the encrypted signature from the subject certificate');
        
        // The issuer's public key is needed to decode the subject signature
        $issuerPublicKey = openssl_pkey_get_public( $issuerCertificate );
        if ( openssl_public_decrypt( $signatureBytes, $decryptedSignature, $issuerPublicKey ) === false )
            throw new \Exception('Unable to decrypt the subject signature using the issuer public key');

        // Being able to decrypt the signature is probably good enough proof but confirming the hashes are the same makes sure the signer certificate is unchanged

        // Access the algorithm and TBS hash from the decoded signature
        $signature = asSequence( (new DerDecoder())->decodeElement( $decryptedSignature ) );
        $hashOID = asObjectIdentifier( $signature->at(1)->asSequence()->at(1) );
        $hashName = \Ocsp\Ocsp::OID2Name[ $hashOID->getIdentifier() ];

        // The hash computed by the issuer is in the signature
        $signatureHash = asOctetString( $signature->at(2) );
    
        // Create a hash of the subject's TBS
        $tbs = (new DerEncoder())->encodeElement( $subjectCertificate->at(1) );
        // And compare it with the one in the signature
        if ( bin2hex( $signatureHash->getValue() ) != hash( $hashName, $tbs ) )
            throw new \Exception('');
     
        return true;
    }

    /**
     * Send a request to an OCSP server
     *
     * @param \Ocsp\Asn1\Element\Sequence $certificate
	 * @param string $caBundlePath (optional: path to the location of a bundle of trusted CA certificates)
     * @return bool
     */
    static function sendRequest( $certificate, $issuerCertificate = null, $caBundlePath = null )
    {
        list( $certificate, $certificateInfo, $ocspResponderUrl, $issuerCertBytes, $issuerCertificate ) = array_values( \Ocsp\Ocsp::getCertificate( $certificate, $issuerCertificate ) );

        /** @var \Ocsp\CertificateInfo $certificateInfo */
        /** @var \Ocsp\Asn1\Element\Sequence $certificate */
        /** @var \Ocsp\Asn1\Element\Sequence $issuerCertificate */

        // Extract the relevant data from the two certificates
        $requestInfo = $certificateInfo->extractRequestInfo($certificate, $issuerCertificate);

        // Build the raw body to be sent to the OCSP Responder URL
        $ocsp = new \Ocsp\Ocsp();
        $requestBody = $ocsp->buildOcspRequestBodySingle($requestInfo);
        // $b64 = base64_encode( $requestBody );

        // Actually call the OCSP Responder URL (here we use cURL, you can use any library you prefer)
        // For a simple debug option use the address of an OpenSSL 
        $result = \Ocsp\Ocsp::doRequest( $ocspResponderUrl, $requestBody, \Ocsp\Ocsp::OCSP_REQUEST_MEDIATYPE, \Ocsp\Ocsp::OCSP_RESPONSE_MEDIATYPE, $caBundlePath );

        $resultB64 = base64_encode( $result );
        // Decode the raw response from the OCSP Responder.  It will throw an error if the ASN 
        // is invalid or the signature is not correct.  Otherwise its necessary to check the 
        // decoded response.
        $response = $ocsp->decodeOcspResponseSingle( $result, $issuerCertBytes );
        return;
    }

    /**
     * Send a request to an OCSP server
     *
     * @param string $path
	 * @param string $caBundlePath (optional: path to the location of a bundle of trusted CA certificates)
     * @return bool
     */
    static function sendRequestForFile( $path, $caBundlePath = null )
    {
        $certificateLoader = new \Ocsp\CertificateLoader();
        $certificate = $certificate = $certificateLoader->fromFile( $path );

        return self::sendRequest( $certificate, $caBundlePath );
    }

    /**
	 * Issue a request to the url passing the body
	 *
	 * @param string $ocspResponderUrl
	 * @param string $requestBody
	 * @return string
	 */
	static function doRequest( $tsaUrl, $requestBody, $requestType, $responseType, $caBundlePath = null )
	{
		$caBundlePath = $caBundlePath ?? __DIR__ . '/cacerts-for-php-curl/cacerts.pem';

		$hCurl = curl_init( );
		curl_setopt_array($hCurl, [
			CURLOPT_URL => $tsaUrl,
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_POST => true,
			CURLOPT_HTTPHEADER => ['Content-Type: ' . $requestType],
			CURLOPT_POSTFIELDS => $requestBody,
			// CURLOPT_CAINFO => $caBundlePath,
		] );
		$result = curl_exec($hCurl);
		$info = curl_getinfo($hCurl);
		if ($info['http_code'] !== 200) 
		{
			throw new \RuntimeException("Whoops, here we'd expect a 200 HTTP code");
		}

		if ( $info['content_type'] !== $responseType )
		{
			throw new \RuntimeException("Whoops, the Content-Type header of the response seems wrong!");
		}

		return $result;
	}

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
    public static function PEMize( $data, $type = 'CERTIFICATE' )
	{
		return "-----BEGIN $type-----\r\n"
		. chunk_split(base64_encode($data))
		. "-----END $type-----\r\n";
	}

    /**
     * Opposite of PEMize
     *
     * @param string $pem_data
     * @return string A string of binary data
     */
    static function pem2der( $pem_data )
    {
        $begin = "CERTIFICATE-----";
        $end   = "-----END";
        $pem_data = substr( $pem_data, strpos( $pem_data, $begin ) + strlen( $begin ) );   
        $pem_data = substr( $pem_data, 0, strpos( $pem_data, $end ) );
        $der = base64_decode($pem_data);
        return $der;
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
		$hashAlg = self::OID2Name[ $ha ];
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
