<?php

namespace Ocsp;

use Ocsp\Asn1\Der\Decoder as DerDecoder;
use Ocsp\Asn1\Der\Encoder as DerEncoder;
use Ocsp\Asn1\Element;
use Ocsp\Asn1\Element\BitString;
use Ocsp\Asn1\Element\Integer;
use Ocsp\Asn1\Element\ObjectIdentifier;
use Ocsp\Asn1\Element\OctetString;
use Ocsp\Asn1\Element\RawPrimitive;
use Ocsp\Asn1\Element\Sequence;
use Ocsp\Asn1\Tag;
use Ocsp\Asn1\UniversalTagID;
use Ocsp\Exception\Asn1DecodingException;

use const Ocsp\Asn1\authorityInfoAccess;
use const Ocsp\Asn1\caIssuers;

class CertificateInfo
{
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
     * Extract the OCSP Responder URL that *may* be included in a certificate.
     *
     * @param \Ocsp\Asn1\Element\Sequence $certificate the certificate (loaded with the CertificateLoader class)
     *
     * @return string empty string if not found
     */
    public function extractOcspResponderUrl(Sequence $certificate)
    {
        $authorityInfoAccess = $this->getAuthorityInfoAccessExtension($certificate);
        if ($authorityInfoAccess === null) {
            return '';
        }
        foreach ($authorityInfoAccess->getElements() as $accessDescription) {
            $accessMethod = $accessDescription instanceof Sequence ? $accessDescription->getFirstChildOfType(UniversalTagID::OBJECT_IDENTIFIER) : null;
            /** @var ObjectIdentifier $accessMethod */
            if ($accessMethod === null || $accessMethod->getIdentifier() !== '1.3.6.1.5.5.7.48.1') {
                continue;
            }
            /** @var Sequence $accessDescription */
            $accessLocation = $accessDescription->getFirstChildOfType(6, Element::CLASS_CONTEXTSPECIFIC);
            if (!$accessLocation instanceof RawPrimitive) {
                return '';
            }
            // It's a IA5String, that is US-ASCII
            return $accessLocation->getRawEncodedValue();
        }

        return '';
    }

    /**
     * Extract the URL where the issuer certificate can be retrieved from (if present).
     *
     * @param \Ocsp\Asn1\Element\Sequence $certificate the certificate (loaded with the CertificateLoader class)
     *
     * @return string empty string if not found
     */
    public function extractIssuerCertificateUrl(Sequence $certificate)
    {
        $authorityInfoAccess = $this->getAuthorityInfoAccessExtension($certificate);
        if ($authorityInfoAccess === null) {
            return '';
        }
        foreach( $authorityInfoAccess->getElements() as $accessDescription )
        {
            $accessMethod = $accessDescription instanceof Sequence ? $accessDescription->getFirstChildOfType(UniversalTagID::OBJECT_IDENTIFIER) : null;
            /** @var ObjectIdentifier $accessMethod */
            if ($accessMethod === null || $accessMethod->getIdentifier() !== \Ocsp\Ocsp::caIssuers ) {
                continue;
            }
            /** @var Sequence $accessDescription */
            $accessLocation = $accessDescription->getFirstChildOfType(6, Element::CLASS_CONTEXTSPECIFIC);
            if (!$accessLocation instanceof RawPrimitive) {
                return '';
            }
            // It's a IA5String, that is US-ASCII
            return $accessLocation->getRawEncodedValue();
        }

        return '';
    }

    /**
     * Extract the data to be sent to the OCSP Responder url from a certificate and the issuer certifiacte.
     *
     * @param \Ocsp\Asn1\Element\Sequence $certificate the certificate (loaded with the CertificateLoader class)
     * @param \Ocsp\Asn1\Element\Sequence $issuerCertificate the issuer certificate (loaded with the CertificateLoader class; its URL can be retrieved with the extractOcspResponderUrl method)
     *
     * @throws \Ocsp\Exception\RequestException when some required data is missing in the certificate/issuer certificate
     *
     * @return \Ocsp\Request
     */
    public function extractRequestInfo(Sequence $certificate, Sequence $issuerCertificate)
    {
        return Request::create(
            $this->extractSerialNumber($certificate),
            $this->extractIssuerDer($certificate),
            $this->extractSubjectPublicKeyBytes($issuerCertificate)
        );
    }

    /**
     * Get the AuthorityInfoAccess extension included in a certificate.
     *
     * @param \Ocsp\Asn1\Element\Sequence $certificate
     *
     * @return \Ocsp\Asn1\Element\Sequence|null
     *
     * @see https://tools.ietf.org/html/rfc2459#section-4.1 for Certificate
     * @see https://tools.ietf.org/html/rfc2459#section-4.2.2.1 for AuthorityInfoAccessSyntax
     */
    protected function getAuthorityInfoAccessExtension(Sequence $certificate)
    {
        $tbsCertificate = $certificate->getFirstChildOfType(UniversalTagID::SEQUENCE, Element::CLASS_UNIVERSAL);
        if (!$tbsCertificate instanceof Sequence) {
            return null;
        }
        $extensions = $tbsCertificate->getFirstChildOfType(3, Element::CLASS_CONTEXTSPECIFIC, Tag::ENVIRONMENT_EXPLICIT);
        if (!$extensions instanceof Sequence) {
            return null;
        }
        foreach ($extensions->getElements() as $extension) {
            if (!$extension instanceof Sequence) {
                continue;
            }
            /** @var Sequence $extension */
            $extnID = $extension->getFirstChildOfType(UniversalTagID::OBJECT_IDENTIFIER);
            /** @var ObjectIdentifier $extnID */
            if ($extnID === null || $extnID->getIdentifier() !== \Ocsp\Ocsp::authorityInfoAccess ) {
                continue;
            }
            /** @var OctetString */
            $extnValue = $extension->getFirstChildOfType(UniversalTagID::OCTET_STRING);
            if ($extnValue === null) {
                return '';
            }
            try {
                $authorityInfoAccess = $this->derDecoder->decodeElement($extnValue->getValue());
            } catch (Asn1DecodingException $foo) {
                $authorityInfoAccess = null;
            }

            return $authorityInfoAccess instanceof Sequence ? $authorityInfoAccess : null;
        }

        return null;
    }

    /**
     * Extract the serial number from a certificate.
     *
     * @param \Ocsp\Asn1\Element\Sequence $certificate
     *
     * @return string Empty string if not found
     *
     * @see https://tools.ietf.org/html/rfc2459#section-4.1 for Certificate
     * @see https://tools.ietf.org/html/rfc5912#section-14 for CertificateSerialNumber
     */
    protected function extractSerialNumber(Sequence $certificate)
    {
        /** @var Sequence */
        $tbsCertificate = $certificate->getFirstChildOfType(UniversalTagID::SEQUENCE);
        if ($tbsCertificate === null) {
            return '';
        }

        /** @var Integer */
        $serialNumber = $tbsCertificate->getFirstChildOfType(UniversalTagID::INTEGER);
        if ($serialNumber === null) {
            return '';
        }

        $encoder = new DerEncoder();
        return $serialNumber->getEncodedValue( $encoder );
    }

    /**
     * Extract the issuer sequence.
     *
     * @param \Ocsp\Asn1\Element\Sequence $certificate
     *
     * @return Sequence Empty string if not found
     *
     * @see https://tools.ietf.org/html/rfc2459#section-4.1 for Certificate
     */
    public function extractIssuer(Sequence $certificate)
    {
        /** @var Sequence */
        $tbsCertificate = $certificate->getFirstChildOfType(UniversalTagID::SEQUENCE);
        if ($tbsCertificate === null) 
        {
            return '';
        }
        return $tbsCertificate->getNthChildOfType(2, UniversalTagID::SEQUENCE) ?? '';
        }

    /**
     * Extract the DER-encoded data of the issuer.
     *
     * @param \Ocsp\Asn1\Element\Sequence $certificate
     *
     * @return string Empty string if not found
     *
     * @see https://tools.ietf.org/html/rfc2459#section-4.1 for Certificate
     */
    protected function extractIssuerDer(Sequence $certificate)
    {
        $issuer = $this->extractIssuer( $certificate );
        return $issuer ? $this->derEncoder->encodeElement( $issuer ) : '';
    }

    /**
     * Extract the bytes of the public key of the subject included in the certificate.
     *
     * @param \Ocsp\Asn1\Element\Sequence $certificate
     *
     * @return string Empty string if not found
     */
    protected function extractSubjectPublicKeyBytes(Sequence $certificate)
    {
        /** @var Sequence */
        $tbsCertificate = $certificate->getFirstChildOfType(UniversalTagID::SEQUENCE);
        if ($tbsCertificate === null) {
            return '';
        }
        /** @var Sequence */
        $subjectPublicKeyInfo = $tbsCertificate->getNthChildOfType(5, UniversalTagID::SEQUENCE);
        if ($subjectPublicKeyInfo === null) {
            return '';
        }
        /** @var BitString */
        $subjectPublicKey = $subjectPublicKeyInfo->getFirstChildOfType(UniversalTagID::BIT_STRING);
        if ($subjectPublicKey === null) {
            return '';
        }

        return $subjectPublicKey->getBytes();
    }
}
