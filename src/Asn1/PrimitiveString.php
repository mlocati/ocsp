<?php

/**
 * Taken from https://github.com/sop/asn1 MIT License Copyright (c) 2016-2021 Joni Eskelinen
 */

namespace Ocsp\Asn1;

use Ocsp\Asn1\Element;
use Ocsp\Asn1\Encoder;
use Ocsp\Asn1\UniversalTagID;

/**
 * Base class for primitive strings.
 *
 * Used by types that don't require special processing of the encoded string data.
 *
 * @internal
 */
abstract class PrimitiveString extends BaseString
{
    /**
     * {@inheritdoc}
     *
     * @see \Ocsp\Asn1\Element::getClass()
     */
    public function getClass()
    {
        return Element::CLASS_UNIVERSAL;
    }

    /**
     * {@inheritdoc}
     *
     * @see \Ocsp\Asn1\Element::isConstructed()
     */
    public function isConstructed()
    {
        return false;
    }

    /**
     * {@inheritdoc}
     *
     * @see \Ocsp\Asn1\Element::getEncodedValue()
     */
    public function getEncodedValue( Encoder $encoder )
    {
        return $this->getValue();
    }

}