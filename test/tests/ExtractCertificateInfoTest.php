<?php

namespace Ocsp\Test;

use Ocsp\CertificateInfo;
use Ocsp\CertificateLoader;
use PHPUnit\Framework\TestCase;

class ExtractCertificateInfoTest extends TestCase
{
    /**
     * @return array[]
     */
    public function extractResponderUrlProvider()
    {
        return [
            ['revoked1.crt', 'http://r3.o.lencr.org', 'http://r3.i.lencr.org/'],
        ];
    }

    /**
     * @dataProvider extractResponderUrlProvider
     *
     * @param string $certificateFilename
     * @param string $expectedResponderUrl
     * @param string $expectedIssuerCertificateUrl
     */
    public function testExtractResponderUrl($certificateFilename, $expectedResponderUrl, $expectedIssuerCertificateUrl)
    {
        $certificateLoader = new CertificateLoader();
        $certificateInfo = new CertificateInfo();
        $certificate = $certificateLoader->fromFile(OCSP_TEST_DIR . '/assets/' . $certificateFilename);
        $extractedResponderUrl = $certificateInfo->extractOcspResponderUrl($certificate);
        $this->assertSame($expectedResponderUrl, $extractedResponderUrl);
        $extractedIssuerCertificateUrl = $certificateInfo->extractIssuerCertificateUrl($certificate);
        $this->assertSame($expectedIssuerCertificateUrl, $extractedIssuerCertificateUrl);
    }
}
