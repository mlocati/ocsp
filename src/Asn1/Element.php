<?php

namespace Ocsp\Asn1;

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
     * Get the type ID.
     *
     * @return int|string|\phpseclib\Math\BigInteger|\phpseclib3\Math\BigInteger
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
