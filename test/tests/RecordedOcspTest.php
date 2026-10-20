<?php

namespace Ocsp\Test;

use DateTimeImmutable;
use Ocsp\Asn1\Der\Decoder;
use Ocsp\Asn1\UniversalTagID;
use Ocsp\CertificateInfo;
use Ocsp\CertificateLoader;
use Ocsp\Ocsp;
use Ocsp\Response;
use Ocsp\Service\Math;
use PHPUnit\Framework\TestCase;

/**
 * Tests against OCSP requests and responses recorded with OpenSSL (see test/assets/ocsp/generate.sh).
 */
class RecordedOcspTest extends TestCase
{
    /**
     * @return array[]
     */
    public function certificateProvider()
    {
        return [
            ['good'],
            ['revoked'],
        ];
    }

    /**
     * @dataProvider certificateProvider
     *
     * @param string $name
     */
    public function testBuiltRequestIdentifiesSameCertificateAsOpenssl($name)
    {
        $ocsp = new Ocsp();
        $requestBody = $ocsp->buildOcspRequestBodySingle(static::extractRequestInfo($name));

        $this->assertSame(
            static::extractCertID(file_get_contents(OCSP_TEST_DIR . "/assets/ocsp/{$name}.request.der")),
            static::extractCertID($requestBody)
        );
    }

    public function testDecodeGoodResponse()
    {
        $ocsp = new Ocsp();
        $response = $ocsp->decodeOcspResponseSingle(file_get_contents(OCSP_TEST_DIR . '/assets/ocsp/good.response.der'));

        $this->assertSame(false, $response->isRevoked());
        $this->assertSame(static::readSerialNumberFromIndex('good'), $response->getCertificateSerialNumber());
        $this->assertSame(static::extractRequestInfo('good')->getCertificateSerialNumber(), $response->getCertificateSerialNumber());
        $this->assertNull($response->getRevokedOn());
        $this->assertNull($response->getRevocationReason());
        $this->assertEquals($response->getThisUpdate()->modify('+7 days'), $response->getNextUpdate());
    }

    public function testDecodeRevokedResponse()
    {
        $ocsp = new Ocsp();
        $response = $ocsp->decodeOcspResponseSingle(file_get_contents(OCSP_TEST_DIR . '/assets/ocsp/revoked.response.der'));

        $this->assertSame(true, $response->isRevoked());
        $this->assertSame(static::readSerialNumberFromIndex('revoked'), $response->getCertificateSerialNumber());
        $this->assertSame(static::extractRequestInfo('revoked')->getCertificateSerialNumber(), $response->getCertificateSerialNumber());
        $this->assertEquals(new DateTimeImmutable('2025-01-02T03:04:05Z'), $response->getRevokedOn());
        $this->assertSame(Response::REVOCATIONREASON_KEYCOMPROMISE, $response->getRevocationReason());
        $this->assertEquals($response->getThisUpdate()->modify('+7 days'), $response->getNextUpdate());
    }

    /**
     * @param string $name
     *
     * @return \Ocsp\Request
     */
    protected static function extractRequestInfo($name)
    {
        $certificateLoader = new CertificateLoader();
        $certificateInfo = new CertificateInfo();

        return $certificateInfo->extractRequestInfo(
            $certificateLoader->fromFile(OCSP_TEST_DIR . "/assets/ocsp/{$name}.crt"),
            $certificateLoader->fromFile(OCSP_TEST_DIR . '/assets/ocsp/ca.crt')
        );
    }

    /**
     * Read the decimal serial number of a certificate from the OpenSSL CA index.
     *
     * @param string $name
     *
     * @return string
     */
    protected static function readSerialNumberFromIndex($name)
    {
        foreach (file(OCSP_TEST_DIR . '/assets/ocsp/index.txt', FILE_IGNORE_NEW_LINES) as $line) {
            $fields = explode("\t", $line);
            if ($fields[5] === "/CN={$name}.test.invalid") {
                return Math::createBigInteger($fields[3], 16)->toString();
            }
        }

        throw new \RuntimeException("Certificate {$name} not found in the index");
    }

    /**
     * Extract the identifying fields of the CertID of the first request in an OCSP request.
     *
     * @param string $requestBody
     *
     * @return array
     */
    protected static function extractCertID($requestBody)
    {
        $decoder = new Decoder();
        $ocspRequest = $decoder->decodeElement($requestBody);
        $tbsRequest = $ocspRequest->getFirstChildOfType(UniversalTagID::SEQUENCE);
        $requestList = $tbsRequest->getFirstChildOfType(UniversalTagID::SEQUENCE);
        $request = $requestList->getFirstChildOfType(UniversalTagID::SEQUENCE);
        $certID = $request->getFirstChildOfType(UniversalTagID::SEQUENCE);
        $hashAlgorithm = $certID->getFirstChildOfType(UniversalTagID::SEQUENCE);

        return [
            'hashAlgorithm' => $hashAlgorithm->getFirstChildOfType(UniversalTagID::OBJECT_IDENTIFIER)->getIdentifier(),
            'issuerNameHash' => bin2hex($certID->getNthChildOfType(1, UniversalTagID::OCTET_STRING)->getValue()),
            'issuerKeyHash' => bin2hex($certID->getNthChildOfType(2, UniversalTagID::OCTET_STRING)->getValue()),
            'serialNumber' => (string) $certID->getFirstChildOfType(UniversalTagID::INTEGER)->getValue(),
        ];
    }
}
