<?php

namespace Ocsp;

use Ocsp\Asn1\Der\Decoder as DerDecoder;
use Ocsp\Asn1\Element\Sequence;
use Ocsp\Exception\Asn1DecodingException;

/**
 * Class to load and decode certificates in PEM (text) / DER (binary) formats.
 */
class CertificateLoader
{
    /**
     * The decoder to be used to decode the loaded certificate.
     *
     * @var \Ocsp\Asn1\Der\Decoder
     */
    private $derDecoder;

    /**
     * Initialize the instance.
     */
    public function __construct()
    {
        $this->derDecoder = new DerDecoder();
    }

    /**
     * Load a certificate from a file.
     *
     * @param string $path
     *
     * @throws \Ocsp\Exception\Asn1DecodingException
     *
     * @return \Ocsp\Asn1\Element\Sequence
     */
    public function fromFile($path)
    {
        if (!is_string($path) || !is_file($path)) {
            throw Asn1DecodingException::create(sprintf('Unable to find the file %s', $path));
        }
        if (!is_readable($path)) {
            throw Asn1DecodingException::create(sprintf('The file %s is not readable', $path));
        }
        $contents = @file_get_contents($path);
        if ($contents === false) {
            throw Asn1DecodingException::create(sprintf('Unable to read the file %s', $path));
        }

        return $this->fromString($contents);
    }

    /**
     * Load a certificate from a string.
     *
     * @param string $data
     *
     * @throws \Ocsp\Exception\Asn1DecodingException
     *
     * @return \Ocsp\Asn1\Element\Sequence
     */
    public function fromString($data)
    {
        $data = (string) $data;
        if ($data === '') {
            throw Asn1DecodingException::create('Empty certificate');
        }
        $data = $this->ensureDer($data);
        $certificate = $this->derDecoder->decodeElement($data);
        if (!$certificate instanceof Sequence) {
            throw Asn1DecodingException::create();
        }

        return $certificate;
    }

    /**
     * Convert (if necessary) a PEM-encoded certificate to DER format.
     * Code from phpseclib, by TerraFrost and other phpseclib contributors (see https://github.com/phpseclib/phpseclib).
     *
     * @param string $data
     *
     * @return string
     */
    protected function ensureDer($data)
    {
        $temp = preg_replace('/.*?^-+[^-]+-+[\r\n ]*$/ms', '', $data, 1);
        $temp = preg_replace('/-+[^-]+-+/', '', $temp);
        $temp = str_replace(["\r", "\n", ' '], '', $temp);
        $temp = preg_match('/^[a-zA-Z\d\/+]*={0,2}$/', $temp) ? @base64_decode($temp, true) : false;

        return $temp ?: $data;
    }
}
