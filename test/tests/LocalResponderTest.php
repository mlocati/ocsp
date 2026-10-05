<?php

namespace Ocsp\Test;

use DateTimeImmutable;
use Ocsp\CertificateInfo;
use Ocsp\CertificateLoader;
use Ocsp\Ocsp;
use Ocsp\Response;
use PHPUnit\Framework\TestCase;

/**
 * Tests the full OCSP flow against the OpenSSL OCSP responder, using the test CA in test/assets/ocsp.
 */
class LocalResponderTest extends TestCase
{
    /**
     * @return array[]
     */
    public function certificateProvider()
    {
        return [
            ['good', false],
            ['revoked', true],
        ];
    }

    /**
     * @dataProvider certificateProvider
     *
     * @param string $name
     * @param bool $expectedRevocation
     */
    public function testResponderStatus($name, $expectedRevocation)
    {
        $certificateLoader = new CertificateLoader();
        $certificateInfo = new CertificateInfo();
        $ocsp = new Ocsp();
        $certificate = $certificateLoader->fromFile(OCSP_TEST_DIR . "/assets/ocsp/{$name}.crt");
        $issuerCertificate = $certificateLoader->fromFile(OCSP_TEST_DIR . '/assets/ocsp/ca.crt');

        $this->assertSame('http://ocsp.test.invalid', $certificateInfo->extractOcspResponderUrl($certificate));

        $requestInfo = $certificateInfo->extractRequestInfo($certificate, $issuerCertificate);
        $response = $ocsp->decodeOcspResponseSingle($this->askResponder($ocsp->buildOcspRequestBodySingle($requestInfo)));

        $this->assertSame($expectedRevocation, $response->isRevoked());
        $this->assertSame($requestInfo->getCertificateSerialNumber(), $response->getCertificateSerialNumber());
        $this->assertLessThanOrEqual(new DateTimeImmutable('+1 minute'), $response->getThisUpdate());
        $this->assertGreaterThan(new DateTimeImmutable(), $response->getNextUpdate());
        if ($expectedRevocation) {
            $this->assertEquals(new DateTimeImmutable('2025-01-02T03:04:05Z'), $response->getRevokedOn());
            $this->assertSame(Response::REVOCATIONREASON_KEYCOMPROMISE, $response->getRevocationReason());
        }
    }

    /**
     * Let the OpenSSL OCSP responder answer a request.
     *
     * @param string $requestBody
     *
     * @return string
     */
    protected function askResponder($requestBody)
    {
        exec('openssl version 2>&1', $output, $exitCode);
        if ($exitCode !== 0) {
            $this->markTestSkipped('The openssl command is not available');
        }

        $directory = OCSP_TEST_DIR . '/assets/ocsp';
        $requestFile = tempnam(sys_get_temp_dir(), 'ocsp');
        $responseFile = tempnam(sys_get_temp_dir(), 'ocsp');
        try {
            file_put_contents($requestFile, $requestBody);
            $command = implode(' ', [
                'openssl ocsp',
                '-index ' . escapeshellarg("{$directory}/index.txt"),
                '-CA ' . escapeshellarg("{$directory}/ca.crt"),
                '-rsigner ' . escapeshellarg("{$directory}/ca.crt"),
                '-rkey ' . escapeshellarg("{$directory}/ca.key"),
                '-reqin ' . escapeshellarg($requestFile),
                '-respout ' . escapeshellarg($responseFile),
                '-ndays 1',
                '2>&1',
            ]);
            $output = [];
            exec($command, $output, $exitCode);
            $this->assertSame(0, $exitCode, implode("\n", $output));

            return file_get_contents($responseFile);
        } finally {
            unlink($requestFile);
            unlink($responseFile);
        }
    }
}
