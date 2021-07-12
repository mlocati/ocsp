<?php

/**
 * TSA support.  Timestamps are used in XADES-T signatures.  Their processing is specified
 * in RFV3161 which relies on definitions in RFC3852. 
 * 
 * Note this is not a general purpose TSA handler.  It makes assumptions such as that an
 * x509 certificate has been use to sign data using RSA and the certificates used will be
 * included in the response (because the flag is set in the request).
 * 
 * Copyright © 2021 Lyquidity Solutions Limited
 * License GPL 3.0.0
 * Bill Seddon 2021-06-15
 */

/*
	A time-stamping response is as follows:

	TimeStampResp ::= SEQUENCE  {
		status                  PKIStatusInfo,
		timeStampToken          TimeStampToken     OPTIONAL  }

	The status is based on the definition of status in section 3.2.3 of [RFC2510] as follows:

	PKIStatusInfo ::= SEQUENCE 
	{
		status        PKIStatus,
		statusString  PKIFreeText     OPTIONAL,
		failInfo      PKIFailureInfo  OPTIONAL
	}

	When the status contains the value zero or one, a TimeStampToken MUST
	be present.  When status contains a value other than zero or one, a
	TimeStampToken MUST NOT be present.  One of the following values MUST
	be contained in status:

	PKIStatus ::= INTEGER 
	{
		granted                (0), -- when the PKIStatus contains the value zero a TimeStampToken, as requested, is present.
		grantedWithMods        (1), -- when the PKIStatus contains the value one a TimeStampToken, with modifications, is present.
		rejection              (2),
		waiting                (3),
		revocationWarning      (4),	-- this message contains a warning that a revocation is imminent
		revocationNotification (5)  -- notification that a revocation has occurred  
	}

	Compliant servers SHOULD NOT produce any other values. Compliant
	clients MUST generate an error if values it does not understand are
	present.

	When the TimeStampToken is not present, the failInfo indicates the
	reason why the time-stamp request was rejected and may be one of the
	following values.

	PKIFailureInfo ::= BIT STRING
	{
		badAlg               (0), unrecognized or unsupported Algorithm Identifier
		badRequest           (2), transaction not permitted or supported
		badDataFormat        (5), the data submitted has the wrong format
		timeNotAvailable    (14), the TSA's time source is not available
		unacceptedPolicy    (15), the requested TSA policy is not supported by the TSA
		unacceptedExtension (16), the requested extension is not supported by the TSA
		addInfoNotAvailable (17), the additional information requested could not be understood or is not available
		systemFailure       (25)  the request cannot be handled due to system failure 
	}

	These are the only values of PKIFailureInfo that SHALL be supported.

	TimeStampToken ::= ContentInfo
		-- contentType is id-signedData ([CMS])
		-- content is SignedData ([CMS])
*/

/*
	$content is a SignedData instance as defined in RFC3852
	The signed-data content type shall have ASN.1 type SignedData:

		SignedData ::= SEQUENCE
		{
			version CMSVersion,
			digestAlgorithms DigestAlgorithmIdentifiers,
			encapContentInfo EncapsulatedContentInfo,
			certificates [0] IMPLICIT CertificateSet OPTIONAL,
			crls [1] IMPLICIT CertificateRevocationLists OPTIONAL,
			signerInfos SignerInfos 
		}

		DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier

		DigestAlgorithmIdentifier ::= SEQUENCE
		{
			identifier	::= OBJECT_IDENTIFIER,
			parameters	::= NULL
		}

		SignerInfos ::= SET OF SignerInfo

	Per-signer information is represented in the type SignerInfo:

		SignerInfo ::= SEQUENCE 
		{
			version 3 or 1,
			sid SignerIdentifier,
			digestAlgorithm DigestAlgorithmIdentifier,
			signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
			signatureAlgorithm SignatureAlgorithmIdentifier,
			signature SignatureValue,
			unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL
		}

		SignerIdentifier ::= CHOICE
		{
			issuerAndSerialNumber IssuerAndSerialNumber,
			subjectKeyIdentifier [0] SubjectKeyIdentifier
		}

		SignedAttributes ::= SET SIZE (1..MAX) OF Attribute

		UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute

		Attribute ::= SEQUENCE 
		{
			attrType OBJECT IDENTIFIER,
			attrValues SET OF AttributeValue
		}

		AttributeValue ::= ANY

		SignatureValue ::= OCTET STRING

	The fields of type SignerInfo have the following meanings:

		version is the syntax version number.  If the SignerIdentifier is the CHOICE issuerAndSerialNumber, 
			then the version shall be 1.  If the SignerIdentifier is subjectKeyIdentifier, then the version
			shall be 3.

		sid specifies the signer's certificate (and thereby the signer's public key).  The signer's 
			public key is needed by the recipient to verify the signature.  SignerIdentifier provides two
			alternatives for specifying the signer's public key.  The issuerAndSerialNumber alternative 
			identifies the signer's certificate by the issuer's distinguished name and the certificate
			serial number; the subjectKeyIdentifier identifies the signer's certificate by the X.509 
			subjectKeyIdentifier extension value.

		digestAlgorithm identifies the message digest algorithm, and any associated parameters, used 
			by the signer.  The message digest is computed on either the content being signed or the 
			content together with the signed attributes using the process described in section 5.4.  
			The message digest algorithm should be among those listed in the digestAlgorithms field of 
			the associated SignerData.

		signedAttributes is a collection of attributes that are signed.  The field is optional, but it must 
			be present if the content type of the EncapsulatedContentInfo value being signed is not id-data.
			Each SignedAttribute in the SET must be DER encoded.  Useful attribute types, such as signing time, 
			are defined in Section 11. If the field is present, it must contain, at a minimum, the following two attributes:

			A content-type attribute having as its value the content type of the EncapsulatedContentInfo 
				value being signed.  Section 11.1 defines the content-type attribute.  The content-type
				attribute is not required when used as part of a countersignature unsigned attribute as 
				defined in section 11.4.

			A message-digest attribute, having as its value the message digest of the content.  
				Section 11.2 defines the message-digest attribute.

		signatureAlgorithm identifies the signature algorithm, and any associated parameters, 
			used by the signer to generate the digital signature.

		signature is the result of digital signature generation, using the message digest and 
			the signer's private key.

		unsignedAttributes is a collection of attributes that are not signed.  The field is optional.
			Useful attribute types, such as countersignatures, are defined in Section 11.

	The fields of type SignedAttribute and UnsignedAttribute have the following meanings:

		attrType indicates the type of attribute.  It is an object identifier.

		attrValues is a set of values that comprise the attribute.  The type of each value in the set 
		can be determined uniquely by attrType.
*/

/*
	The time-stamp token MUST NOT contain any signatures other than the
	signature of the TSA.  The certificate identifier (ESSCertID) of the
	TSA certificate MUST be included as a signerInfo attribute inside a
	SigningCertificate attribute.

	TSTInfo ::= SEQUENCE
	{
		version                      INTEGER  { v1(1) },
		policy                       TSAPolicyId,
		messageImprint               MessageImprint, -- MUST have the same value as the similar field in TimeStampReq
		serialNumber                 INTEGER,		 -- Time-Stamping users MUST be ready to accommodate integers up to 160 bits.
		genTime                      GeneralizedTime,
		accuracy                     Accuracy                 OPTIONAL,
		ordering                     BOOLEAN             DEFAULT FALSE,
		nonce                        INTEGER                  OPTIONAL, 	MUST be present if the similar field was present in TimeStampReq.  
																			In that case it MUST have the same value.
		tsa                          [0] GeneralName          OPTIONAL,
		extensions                   [1] IMPLICIT Extensions   OPTIONAL
	}

	MessageImprint ::= SEQUENCE
	{
		hashAlgorithm                AlgorithmIdentifier,
		hashedMessage                OCTET STRING  
	}

	The version field (currently v1) describes the version of the time-stamp token.
*/

namespace Ocsp;

use Ocsp\Asn1\Der\Decoder;
use Ocsp\Asn1\Der\Encoder;
use Ocsp\Asn1\Element;
use Ocsp\Asn1\Element\Boolean;
use Ocsp\Asn1\Element\Integer;
use Ocsp\Asn1\Element\NullElement;
use Ocsp\Asn1\Element\ObjectIdentifier;
use Ocsp\Asn1\Element\OctetString;
use Ocsp\Asn1\Element\Sequence;
use Ocsp\Asn1\Element\Set;
use Ocsp\Asn1\Tag;
use Ocsp\Asn1\UniversalTagID;
use Ocsp\CertificateInfo;

use function Ocsp\Asn1\asBitString;
use function Ocsp\Asn1\asInteger;
use function Ocsp\Asn1\asObjectIdentifier;
use function Ocsp\Asn1\asOctetString;
use function Ocsp\Asn1\asRawConstructed;
use function Ocsp\Asn1\asSequence;
use function Ocsp\Asn1\asSet;
use function Ocsp\Asn1\asUTF8String;

/**
 * Implements functions to create a request, send it to a time-stamp authority, receive and verify a response
 */
class TSA
{
	// The address of the TSA service to use
	const TSAUrl = 'https://freetsa.org/tsr';
	const hashAlg = 'SHA512';

	// Codes used in a response
	const badAlg = 0;
	const badRequest = 2;
	const badDataFormat = 5;
	const timeNotAvailable = 14;
	const unacceptedPolicy = 15;
	const unacceptedExtension = 16;
	const addInfoNotAvailable = 17;
	const systemFailure = 25;

	/**
	 * Call to request and validate a timestamp.  If successful returns the timestamp token (TST) DER encoded as a string
	 * @param string $data The data to be timestamped
	 * @param string $caBundlePath (optional: path to the location of a bundle of trusted CA certificates)
	 * @param string $tsaURL The URL of a Timestamp authority (TSA) to use.  https://freetsa.org/tsr will be used by default
	 * @return DER encode TST returned from the TSA
	 */
	public static function getTimestamp( $data, $caBundlePath = null, $tsaURL = null )
	{
		$hash = hash( self::hashAlg, $data, true );

		$tsaURL = $tsaURL ?? self::TSAUrl;

		// Create a request
		$tsq = Sequence::create( [
			Integer::create(1),
			Sequence::create( [
				Sequence::create( [
					ObjectIdentifier::create( OID::getOIDFromName( self::hashAlg ) ),
					NullElement::create()
				] ),
				OctetString::create( $hash )
			] ),
			Boolean::create( true )
		] );

		// Make the request and receive the response
		$requestBody = ( new Encoder() )->encodeElement( $tsq );
		// $response = self::doRequest( $tsaURL	, $requestBody, 'application/timestamp-query', 'application/timestamp-reply', $caBundlePath );
		// if ( $response === false ) 
		//	throw new \Exception('The request was not successful');

		$response = file_get_contents('d:/GitHub/ocsp/freetsa.tsr');

		// Process the response
		$tsr = asSequence( (new Decoder())->decodeElement( $response ) );

		$status = $tsr->at(1)->asSequence();
		$statusValue = asInteger( $status->at(1) );
	
		if ( ! $statusValue )
			throw new \Exception('Invalid TSR status value');
	
		if ( $statusValue->getValue() != 0 )
		{
			$message = '';
			$statusMessage = asUTF8String( $status->at(2)->asSequence()->at(1) );
			if ( $statusMessage )
			{
				$message = $statusMessage->getValue();
			}
			$statusInfo = asBitString( $status->at(3) );
			if ( $statusInfo )
			{
				$info = Integer::decodeInteger( $statusInfo->getBytes() );
				if ( $info )
				{
					switch( $info )
					{
						case self::badAlg:
							$message = "Unrecognized or unsupported Algorithm Identifier";
							break;
						case self::badRequest:
							$message = "Transaction not permitted or supported";
							break;
						case self::badDataFormat:
							$message = "The data submitted has the wrong format";
							break;
						case self::timeNotAvailable:
							$message = "The TSA's time source is not available";
							break;
						case self::unacceptedPolicy:
							$message = "The requested TSA policy is not supported by the TSA";
							break;
						case self::unacceptedExtension:
							$message = "The requested extension is not supported by the TSA";
							break;
						case self::addInfoNotAvailable:
							$message = "The additional information requested could not be understood or is not available";
							break;
						case self::systemFailure:
							$message = "The request cannot be handled due to system failure";
							break;
						default:
							$message .= " Unknown reason ($info)";
							break;
					}
				}
			}
	
			throw new \Exception( $message );
		}

		// Everything looks good so far so begin processing the TST
		$timestampToken = $tsr->at(2)->asSequence();

		// Check the OID required by RFC3161
		if ( ! ( $oid = asObjectIdentifier( $timestampToken->at(1) ) ) || $oid->getIdentifier() != OID::getOIDFromName('id-signedData') )
		{
			throw new \Exception('Expected Timestamp Token OID to be \'id-signedData\'');
		}

		// Retrieve the section containing the signed information
		$signedData = asSequence( $timestampToken->getNthChildOfType( 1, 0, Element::CLASS_CONTEXTSPECIFIC, Tag::ENVIRONMENT_EXPLICIT ) );

		// $version = asInteger( $signedData->getFirstChildOfType( UniversalTagID::INTEGER ) );

		// Retrieve the identifiers
		// $algorithmIdentifiers = array_reduce( asSet( $signedData->getFirstChildOfType( UniversalTagID::SET ) )->getElements(), 
		// 	function( $carry, Element\Sequence $seq )
		// 	{
		// 		$identifier = asObjectIdentifier( $seq->getFirstChildOfType( UniversalTagID::OBJECT_IDENTIFIER ) )->getIdentifier();
		// 		$carry[ \PKIX\OID::getNameFromOID($identifier ) ] = $identifier;
		// 		return $carry;
		// 	}, array() );

		// The raw timestamped input is held DER encoded in an octet string
		$tst = asSequence( $signedData->getFirstChildOfType( UniversalTagID::SEQUENCE ) );
		// Check the OID required by RFC3161
		if ( ! $tst || 
			( ! $tstInfoOID = asObjectIdentifier( $tst->getFirstChildOfType( UniversalTagID::OBJECT_IDENTIFIER ) ) ) || 
			$tstInfoOID->getIdentifier() != OID::getOIDFromName('id-ct-TSTInfo') )
		{
			throw new \Exception('Expected Timestamp content info OID to \'id-ct-TSTInfo\'');
		}
	
		// Inflate the string to retrieve the decoded content
		$tstInfoRaw = asOctetString( $tst->getFirstChildOfType( 0, Element::CLASS_CONTEXTSPECIFIC, Tag::ENVIRONMENT_EXPLICIT ) );
		if ( ! $tstInfoRaw )
		{
			throw new \Exception('Expect TST info octet string');
		}
	
		// $tstInfo = asSequence( (new Decoder())->decodeElement( $tstInfoRaw->getValue() ) );
		// $tsVersion = asInteger( $tstInfo->getFirstChildOfType( UniversalTagID::INTEGER ) );
		// $tsPpolicyId = asObjectIdentifier( $tstInfo->getFirstChildOfType( UniversalTagID::OBJECT_IDENTIFIER ) );
		// $tsSerial= asInteger( $tstInfo->getNthChildOfType( 2, UniversalTagID::INTEGER ) );
		// $messageImprint = asSequence( $tstInfo->getFirstChildOfType( UniversalTagID::SEQUENCE ) );
		// $messageOctet = asOctetString( $messageImprint->getFirstChildOfType( UniversalTagID::OCTET_STRING ) );

		$signerInfos = \Ocsp\Asn1\asSet( $signedData->getNthChildOfType( 2, \Ocsp\Asn1\UniversalTagID::SET ) );
		// Although the signer is stored in a SET there should be only one
		if ( ! $signerInfos || count( $signerInfos->getElements() ) == 0 || ! $signerInfo = $signerInfos->at(1)->asSequence() )
			throw new \Exception('There are no signer infos in the response');

		// Get the certificate used for signing
		$certificate = self::getCertificateForSigner( $signedData, $signerInfo );
		if ( ! $certificate )
			throw new \Exception('Unable to locate the certificate used to sign the timestamp in the response');

		// The dates on the signing certificate must be valid
		$certificateInfo = new CertificateInfo();
		$dates = $certificateInfo->extractDates( $certificate );
		if ( ! $dates )
			throw new \Exception('The certificate does not contain start/end dates');

		$now = new \DateTimeImmutable("now");
		if ( $dates['start']->getTimestamp() > $now->getTimestamp() )
			throw new \Exception('The signing certificate start date falls in the future');
		if ( $dates['end']->getTimestamp() < $now->getTimestamp() )
			throw new \Exception('The signing certificate has expired');

		// Find the issuer cerificiate in the response
		$issuerCertificate = self::getIssuerCertificate( $signedData );

		// The dates on the issuer certificate must be valid
		$dates = $certificateInfo->extractDates( $issuerCertificate );
		if ( ! $dates )
			throw new \Exception('The issuer certificate does not contain start/end dates');

		if ( $dates['start']->getTimestamp() > $now->getTimestamp() )
			throw new \Exception('The issuer certificate start date falls in the future');
		if ( $dates['end']->getTimestamp() < $now->getTimestamp() )
			throw new \Exception('The issuer certificate has expired');

		// And use it to validate the signer's certificate
		\Ocsp\Ocsp::validateCertificate( $certificate, $issuerCertificate );

		$verified = self::verifyTimestamp( $signerInfo, $tstInfoRaw->getValue(), $certificate, $signedData );

		// Make sure the signer certificate is not revoked
		// Checking the revokation status of a signer cetificate just used seems excessive
		// It will be needed when the timestamp is checked when part of a signed document
		// $response = \Ocsp\Ocsp::sendRequest( $certificate, $issuerCertificate, $caBundlePath );

		return (new Encoder())->encodeElement( $timestampToken );
	}

	/**
	 * Issue a request to the url passing the body
	 *
	 * @param string $ocspResponderUrl
	 * @param string $requestBody
	 * @return string
	 */
	private static function doRequest( $tsaUrl, $requestBody, $requestType, $responseType, $caBundlePath = null )
	{
		$caBundlePath = $caBundlePath ?? __DIR__ . '/cacerts-for-php-curl/cacerts.pem';

		$hCurl = curl_init( );
		curl_setopt_array($hCurl, [
			CURLOPT_URL => $tsaUrl,
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_POST => true,
			CURLOPT_HTTPHEADER => ['Content-Type: ' . $requestType],
			CURLOPT_POSTFIELDS => $requestBody,
			CURLOPT_CAINFO => $caBundlePath,
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
	 * Returns a certificate sequence for a specific signerInfo
	 *
	 * @param Sequence $signedData
	 * @param Sequence $signerInfo
	 * @return Sequence
	 */
	private static function getCertificateForSigner( $signedData, $signerInfo )
	{
		if ( ! $signedData || ! $signerInfo ) return null;

		// Get the certificates 
		$certificates = \Ocsp\Asn1\asRawConstructed( $signedData-> getNthUntaggedChild( 1, \Ocsp\Asn1\Element::CLASS_CONTEXTSPECIFIC, 0 ) );
		if ( ! $certificates ) return null;

		// The version indicates what type of certificate identifier is being used: 1 is subject info and serial number; 2 is subjectKeyId
		$version = \Ocsp\Asn1\asInteger( $signerInfo->at(1) )->getValue();
		if ( ! $version ) return null;

		$certificateSearchValue = null;

		switch( $version )
		{
			case 1:
				// Get the serial number
				$signerIdentifier = \Ocsp\Asn1\asSequence( $signerInfo->at(2) );
				if ( ! $signerIdentifier ) return null;

				$serialNumber = asInteger( $signerIdentifier->getFirstChildOfType( UniversalTagID::INTEGER ) );
				if ( ! $serialNumber ) return null;
		
				$certificateSearchValue = $serialNumber->getEncodedValue( new Encoder() );
				break;
			case 3:
				// TODO: Don't have and example of this type of response yet
				break;
			default:
				// Undefined
				return null;
		}

		if ( ! $certificateSearchValue ) return null;

		$info = new \Ocsp\CertificateInfo();

		foreach( $certificates->getElements() as $cert )
		{
			if ( $version == 1 )
			{
				$serialNumber = $info->extractSerialNumber( $cert );
				if ( $serialNumber == $certificateSearchValue ) return $cert;
			}
			else
			{
				// TODO Need an example
				$subjectId = $info->extractSubjectIdentifier( $cert );
			}
		}

		return null;
	}

	/**
	 * Get the issuer certificate if there is one
	 *
	 * @param Sequence $signedData
	 * @return Sequence
	 */
	static function getIssuerCertificate( $signedData )
	{
		if ( ! $signedData ) return null;

		// Get the certificates 
		$certificates = \Ocsp\Asn1\asRawConstructed( $signedData-> getNthUntaggedChild( 1, \Ocsp\Asn1\Element::CLASS_CONTEXTSPECIFIC, 0 ) );
		if ( ! $certificates ) return null;

		// It will be the second certificate if it exists
		return asSequence( $certificates->at(2) );
	}

	/**
	 * Uses relevant response data to verify the timestamp
	 *
	 * @param Sequence $signerInfo		The information about the entity signing
	 * @param string $timestampRaw		The information that has been signed
	 * @param Sequence $certificate		The certificate containing the public key for verification
	 * @param Sequence $signedData		All the signed data in the response
	 * @return boolean
	 */
	private static function verifyTimestamp( $signerInfo, $timestampRaw, $certificate, $signedData )
	{
		/*
			From RFC3852

			5.4 Message Digest Calculation Process

			The message digest calculation process computes a message digest on either the content being signed or 
			the content together with the signed attributes.  In either case, the initial input to the message digest 
			calculation process is the "value" of the encapsulated content being signed.  Specifically, the initial 
			input is the encapContentInfo eContent OCTET STRING to which the signing process is applied.  Only the 
			octets comprising the value of the eContent OCTET STRING are input to the message digest algorithm, not 
			the tag or the length octets.

			The result of the message digest calculation process depends on whether the signedAttributes field is 
			present.  When the field is absent, the result is just the message digest of the content as described 
			above.  When the field is present, however, the result is the message digest of the complete DER encoding 
			of the SignedAttributes value contained in the signedAttributes field.

			Since the SignedAttributes value, when present, must contain the content type and the content message 
			digest attributes, those values are indirectly included in the result.  The content type attribute is
			not required when used as part of a countersignature unsigned attribute as defined in section 11.4.  
			A separate encoding of the signedAttributes field is performed for message digest calculation.

			The IMPLICIT [0] tag in the signedAttributes field is not used for the DER encoding, rather an EXPLICIT 
			SET OF tag is used.  That is, the DER encoding of the SET OF tag, rather than of the IMPLICIT [0] tag, 
			is to be included in the message digest calculation along with the length and content octets of the 
			SignedAttributes value.

			When the signedAttributes field is absent, then only the octets comprising the value of the signedData 
			encapContentInfo eContent OCTET STRING (e.g., the contents of a file) are input to the message digest 
			calculation.  This has the advantage that the length of the content being signed need not be known in 
			advance of the signature generation process.

			Although the encapContentInfo eContent OCTET STRING tag and length octets are not included in the message 
			digest calculation, they are still protected by other means.  The length octets are protected by the nature 
			of the message digest algorithm since it is computationally infeasible to find any two distinct messages 
			of any length that have the same message digest.

			5.5  Message Signature Generation Process

			The input to the signature generation process includes the result of the message digest calculation process 
			and the signer's private key.  	The details of the signature generation depend on the signature algorithm 
			employed.  The object identifier, along with any parameters, that specifies the signature algorithm employed
			by the signer is carried in the signatureAlgorithm field.  The signature value generated by the signer is 
			encoded as an OCTET STRING and carried in the signature field.

			5.6  Message Signature Verification Process

			The input to the signature verification process includes the result of the message digest calculation process 
			and the signer's public key.  The recipient may obtain the correct public key for the signer by any means, 
			but the preferred method is from a certificate obtained from the SignedData certificates field.  The selection 
			and validation of the signer's public key may be based on certification path validation (see [PROFILE]) as 
			well as other external context, but is 	beyond the scope of this document.  The details of the signature
			verification depend on the signature algorithm employed.

			The recipient may not rely on any message digest values computed by the originator.  If the signedData 
			signerInfo includes signedAttributes, then the content message digest must be calculated as described in 
			section 5.4.  For the signature to be valid, the message digest value calculated by the recipient must be the 
			same as the value of the messageDigest attribute included in the signedAttributes of the signedData signerInfo.
		 */

		// Get the algorithm used
		$digestAlgorithm = asObjectIdentifier( 
			$signerInfo
				->getNthChildOfType( 2, UniversalTagID::SEQUENCE )->asSequence()
				->getFirstChildOfType( UniversalTagID::OBJECT_IDENTIFIER )
		);

		if ( ! $digestAlgorithm )
			throw new \Exception('Unable to find a digest algorithm in the signers info');

		$digestAlgoritmName = OID::getNameFromOID( $digestAlgorithm->getIdentifier() );
		if ( ! $digestAlgoritmName )
			throw new \Exception("The digest algorithm OID '{$digestAlgorithm->getIdentifier()}' is not recognized");

		// Hash the tstInfoRaw using the digest algorithm
		$hash = hash( $digestAlgoritmName, $timestampRaw, true );

		// Get the signed attributes 
		$signedAttributes = asRawConstructed( $signerInfo->getFirstChildOfType( 0, Element::CLASS_CONTEXTSPECIFIC ) );
		// For throw an error.  The specification says that if there are no signed 
		// attributes then the signature should be on the timestamp raw
		if ( ! $signedAttributes )
			throw new \Exception('Unable to find signed attributes.');

		// Find the computed message digest
		$messageDigestOID = OID::getOIDFromName('id-messageDigest');
		$messageDigest = null; 
		foreach( $signedAttributes->getElements() as $attribute )
		{
			$attribute = asSequence( $attribute );
			if ( ! $attribute ) continue;

			$oid = asObjectIdentifier( $attribute->getFirstChildOfType( UniversalTagID::OBJECT_IDENTIFIER ) );
			if ( ! $oid || $oid->getIdentifier() != $messageDigestOID ) continue;

			$set = asSet( $attribute->getFirstChildOfType( UniversalTagID::SET ) );
			if ( ! $set ) break;
			$octet = asOctetString( $set->getFirstChildOfType( UniversalTagID::OCTET_STRING ) );
			if ( ! $octet ) continue;

			$messageDigest = $octet->getValue();
		}

		if ( ! $messageDigest )
			throw new \Exception('Unable to find the message digest in the signer info');

		// Check the hashes match
		if ( $messageDigest != $hash )
			throw new \Exception('The computed hash of the signed timestamp does not match the hash generated by the TSA');

		// Need to create a SET of the signed attributes to hash
		$set = Set::create( $signedAttributes->getElements() ); // ->setTag( Tag::explicit( UniversalTagID::SET ) );
		$enc = (new Encoder())->encodeElement( $set );

		// Verify the signature
		$signature = asOctetString( $signerInfo->getFirstChildOfType( UniversalTagID::OCTET_STRING ) );
		if ( ! $signature )
			throw new \Exception('Unable to find the signature');

		$pem = \Ocsp\Ocsp::PEMize( (new Encoder())->encodeElement( $certificate ) );
		$publicKey = openssl_pkey_get_public( $pem );

		/** @var \OpenSSLAsymmetricKey $ca_pkey */
		$ca_pkey_details = openssl_pkey_get_details( $publicKey );

		if ( $ca_pkey_details === false )
			throw new \Exception('Public key not valid');

		$ca_pkey_type = $ca_pkey_details['type'];
		$algs_cipher = array( OPENSSL_KEYTYPE_RSA, OPENSSL_KEYTYPE_DSA, OPENSSL_KEYTYPE_DH, OPENSSL_KEYTYPE_EC );

		if ( ! in_array( $ca_pkey_type, $algs_cipher ) )
			throw new \Exception('The cipher used by the public key is not supported');

		$algorithm = OID::getOpenSSLAlgorithm( $digestAlgoritmName );

		$result = openssl_verify( $enc, $signature->getValue(), $publicKey, $algorithm );

		if ( $result != 1 )
			throw new \Exception('The response signature cannot be verified');

		return true;
	}
}