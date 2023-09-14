<?php

namespace Ocsp\Test;

use DateTimeImmutable;
use Ocsp\Asn1\Element\Sequence;
use Ocsp\CertificateInfo;
use Ocsp\CertificateLoader;
use Ocsp\Ocsp;
use PHPUnit\Framework\TestCase;

class RevocationTest extends TestCase
{
    /**
     * @return array[]
     */
    public function remoteCertificatesProvider()
    {
        return [
            ['https://www.google.com', false],
            ['https://digicert-tls-ecc-p384-root-g5-revoked.chain-demos.digicert.com/', true]
        ];
    }

    /**
     * @dataProvider remoteCertificatesProvider
     *
     * @param string $url
     * @param bool|null $expectedRevocation
     */
    public function testWithRemoteCertificate($url, $expectedRevocation)
    {
        $certificateLoader = new CertificateLoader();
        $hCurl = curl_init($url);
        try {
            curl_setopt($hCurl, CURLOPT_RETURNTRANSFER, false);
            curl_setopt($hCurl, CURLOPT_CUSTOMREQUEST, 'HEAD');
            curl_setopt($hCurl, CURLOPT_NOBODY, true);
            curl_setopt($hCurl, CURLOPT_CERTINFO, true);
            curl_setopt($hCurl, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($hCurl, CURLOPT_SSL_VERIFYHOST, 0);
            curl_exec($hCurl);
            $certInfo = curl_getinfo($hCurl, CURLINFO_CERTINFO);
            if (!isset($certInfo[1]['Cert'])) {
                $this->markTestSkipped('Failed to retrieve the certificates for ' . $url);
            }
            $certificate = $certificateLoader->fromString($certInfo[0]['Cert']);
            $issuerCertificate = $certificateLoader->fromString($certInfo[1]['Cert']);
            $this->checkRevocation($certificate, $issuerCertificate, $expectedRevocation);
        } finally {
            curl_close($hCurl);
        }
    }

    /**
     * @param \Ocsp\Asn1\Element\Sequence $certificate
     * @param \Ocsp\Asn1\Element\Sequence $issuerCertificate
     * @param bool|null $expectedRevocation
     */
    protected function checkRevocation(Sequence $certificate, Sequence $issuerCertificate, $expectedRevocation)
    {
        $certificateInfo = new CertificateInfo();
        $ocsp = new Ocsp();
        $ocspResponderUrl = $certificateInfo->extractOcspResponderUrl($certificate);
        $requestInfo = $certificateInfo->extractRequestInfo($certificate, $issuerCertificate);
        $requestBody = $ocsp->buildOcspRequestBodySingle($requestInfo);

        $hCurl = curl_init();
        try {
            curl_setopt($hCurl, CURLOPT_URL, $ocspResponderUrl);
            curl_setopt($hCurl, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($hCurl, CURLOPT_POST, true);
            curl_setopt($hCurl, CURLOPT_HTTPHEADER, ['Content-Type: ' . Ocsp::OCSP_REQUEST_MEDIATYPE]);
            curl_setopt($hCurl, CURLOPT_SAFE_UPLOAD, true);
            curl_setopt($hCurl, CURLOPT_POSTFIELDS, $requestBody);
            $result = curl_exec($hCurl);
            $info = curl_getinfo($hCurl);
            $this->assertSame(200, $info['http_code']);
            $this->assertSame(Ocsp::OCSP_RESPONSE_MEDIATYPE, $info['content_type']);
            $response = $ocsp->decodeOcspResponseSingle($result);
            $this->assertSame($expectedRevocation, $response->isRevoked());
            if (!$expectedRevocation) {
                $this->assertSame(DateTimeImmutable::class, get_class($response->getNextUpdate()));
                $this->assertSame(true, $response->getNextUpdate() > new DateTimeImmutable());
            }
        } finally {
            curl_close($hCurl);
        }
    }
}
