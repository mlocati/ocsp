<?php

namespace Ocsp;

use Ocsp\Exception\RequestException;

/**
 * Contains the data to be included in the OCSP request.
 */
class Request
{
    /**
     * The serial number of the certificate.
     *
     * @var string
     */
    private $certificateSerialNumber;

    /**
     * The DER-encoded data of the issuer.
     *
     * @var string
     */
    private $issuerNameDer;

    /**
     * The bytes of the public key of the subject included in the certificate.
     *
     * @var string
     */
    private $issuerPublicKeyBytes;

    protected function __construct()
    {
    }

    /**
     * Create a new instance.
     *
     * @param string $certificateSerialNumber
     * @param string $issuerNameDer
     * @param string $issuerPublicKeyBytes

     *
     * @throws \Ocsp\Exception\RequestException when there's some invalid value
     *
     * @return static
     */
    public static function create($certificateSerialNumber, $issuerNameDer, $issuerPublicKeyBytes)
    {
        $result = new static();

        $certificateSerialNumber = (string) $certificateSerialNumber;
        if ($certificateSerialNumber === '') {
            throw RequestException::create('Missing the certificate serial number');
        }
        $result->certificateSerialNumber = $certificateSerialNumber;

        $issuerNameDer = (string) $issuerNameDer;
        if ($issuerNameDer === '') {
            throw RequestException::create('Missing the issuer details from the certificate');
        }
        $result->issuerNameDer = $issuerNameDer;

        $issuerPublicKeyBytes = (string) $issuerPublicKeyBytes;
        if ($issuerPublicKeyBytes === '') {
            throw RequestException::create('Missing the issuer public key from the issuer certificate');
        }
        $result->issuerPublicKeyBytes = $issuerPublicKeyBytes;

        return $result;
    }

    /**
     * Get tThe serial number of the certificate.
     *
     * @return string
     */
    public function getCertificateSerialNumber()
    {
        return $this->certificateSerialNumber;
    }

    /**
     * Get the DER-encoded data of the issuer.
     *
     * @return string
     */
    public function getIssuerNameDer()
    {
        return $this->issuerNameDer;
    }

    /**
     * Get the bytes of the public key of the subject included in the certificate.
     *
     * @return string
     */
    public function getIssuerPublicKeyBytes()
    {
        return $this->issuerPublicKeyBytes;
    }
}
