<?php

namespace Ocsp\Asn1;

use Ocsp\Asn1\Element\BitString;
use Ocsp\Asn1\Element\Boolean;
use Ocsp\Asn1\Element\Enumerated;
use Ocsp\Asn1\Element\GeneralizedTime;
use Ocsp\Asn1\Element\Integer;
use Ocsp\Asn1\Element\ObjectIdentifier;
use Ocsp\Asn1\Element\OctetString;
use Ocsp\Asn1\Element\RawConstructed;
use Ocsp\Asn1\Element\RawPrimitive;
use Ocsp\Asn1\Element\Sequence;
use Ocsp\Asn1\Util\BigInteger;

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
    '2.16.840.1.101.3.4.2.1' => 'SHA254',
    '2.16.840.1.101.3.4.2.2' => 'SHA384',
    '2.16.840.1.101.3.4.2.3' => 'SHA512',
    '2.16.840.1.101.3.4.2.4' => 'SHA224',
    '1.3.14.3.2.26' => 'SHA1',
    '1.2.840.113549.2.5' => 'MD5'
);

const id_pkix_ocsp_basic = '1.3.6.1.5.5.7.48.1.1';
const authorityInfoAccess = '1.3.6.1.5.5.7.1.1';
const caIssuers = '1.3.6.1.5.5.7.48.2';
const sha256WithRSAEncryption = '1.2.840.113549.1.1.11';

/**
 * Interface that all the ASN.1 elements must implement.
 */
interface Element
{
    /**
     * Class: UNIVERSAL.
     *
     * @var string
     */
    const CLASS_UNIVERSAL = 'UNIVERSAL';

    /**
     * Class: APPLICATION class.
     *
     * @var string
     */
    const CLASS_APPLICATION = 'APPLICATION';

    /**
     * Class: PRIVATE.
     *
     * @var string
     */
    const CLASS_PRIVATE = 'PRIVATE';

    /**
     * Class: context-specific class.
     *
     * @var string
     */
    const CLASS_CONTEXTSPECIFIC = '';

    /**
     * Return a Sequence or null
     *
     * @return Sequence
     */
    public function asSequence();

    /**
     * Get the type ID.
     *
     * @return int|string|BigInteger
     */
    public function getTypeID();

    /**
     * Get the class (the value of one of the Element::CLASS_... constants).
     *
     * @return string
     */
    public function getClass();

    /**
     * Is this a constructed element (that is, does the element contain other elements)?
     *
     * @return bool
     */
    public function isConstructed();

    /**
     * Get the encoded value of the element.
     *
     * @param \Ocsp\Asn1\Encoder $encoder
     *
     * @throws \Ocsp\Exception\Asn1EncodingException
     *
     * @return string
     */
    public function getEncodedValue(Encoder $encoder);
}
