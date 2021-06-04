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

/**
 * Returns type of Sequence if Sequence or null
 *
 * @param Element $element
 * @return Sequence
 */
function asSequence( $element )
{
    return  $element instanceof Sequence
        ? $element 
        : null;
};

/**
 * Returns type of ObjectIdentifier if ObjectIdentifier or null
 *
 * @param Element $element
 * @return ObjectIdentifier
 */
function asObjectIdentifier( $element )
{
    return  $element instanceof ObjectIdentifier
        ? $element 
        : null;
};

/**
 * Returns type of OctetString if OctetString or null
 *
 * @param Element $element
 * @return OctetString
 */
function asOctetString( $element )
{
    return $element instanceof OctetString
        ? $element 
        : null;
};

/**
 * Returns type of Integer if Integer or null
 *
 * @param Element $element
 * @return Integer
 */
function asInteger( $element )
{
    return $element instanceof Integer
        ? $element
        : null;
};

/**
 * Returns type of Boolean if Boolean or null
 *
 * @param Element $element
 * @return Boolean
 */
function asBoolean( $element )
{
    return $element  instanceof Boolean
        ? $element 
        : null;
};

/**
 * Returns type of RawPrimitive if RawPrimitive or null
 *
 * @param Element $element
 * @return RawPrimitive
 */
function asRawPrimitive( $element )
{
    return $element instanceof RawPrimitive
        ?  $element 
        : null;
};

/**
 * Returns type of GeneralizedTime if GeneralizedTime or null
 *
 * @param Element $element
 * @return GeneralizedTime
 */
function asGeneralizedTime( $element )
{
    return $element instanceof GeneralizedTime
        ? $element 
        : null;
};

/**
 * Returns type of BitString if BitString or null
 *
 * @param Element $element
 * @return BitString
 */
function asBitString( $element )
{
    return $element instanceof BitString
        ? $element 
        : null;
};

/**
 * Returns type of Enumerated if Enumerated or null
 *
 * @param Element $element
 * @return Enumerated
 */
function asEnumerated( $element )
{
    return $element instanceof Enumerated
        ? $element 
        : null;
};

/**
 * Returns type of RawConstructed if RawConstructed or null
 *
 * @param Element $element
 * @return RawConstructed
 */
function asRawConstructed( $element )
{
    return $element instanceof RawConstructed
        ? $element 
        : null;
};

/**
 * Interface that any ASN.1 element that can be tagged must implement.
 */
abstract class TaggableElement implements Element
{
    /**
     * The applied tag (if any).
     *
     * @var \Ocsp\Asn1\Tag
     */
    private $tag;

    /**
     * Return a Sequence or null
     *
     * @return Sequence
     */
    public function asSequence()
    {
        return asSequence( $this );
    }

    /**
     * {@inheritdoc}
     *
     * @see \Ocsp\Asn1\TaggableElement::getTag()
     */
    public function getTag()
    {
        return $this->tag;
    }

    /**
     * {@inheritdoc}
     *
     * @see \Ocsp\Asn1\TaggableElement::setTag()
     */
    public function setTag(Tag $value = null)
    {
        $this->tag = $value;

        return $this;
    }

}
