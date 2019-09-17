<?php

namespace Ocsp\Asn1\Element;

use Ocsp\Asn1\UniversalTagID;

/**
 * ASN.1 element: SEQUENCE / SEQUENCE OF.
 */
class Sequence extends AbstractList
{
    /**
     * {@inheritdoc}
     *
     * @see \Ocsp\Asn1\Element::getTypeID()
     */
    public function getTypeID()
    {
        return UniversalTagID::SEQUENCE;
    }

    /**
     * Create a new instance.
     *
     * @param \Ocsp\Asn1\Element[] $elements
     *
     * @return static
     */
    public static function create(array $elements = [])
    {
        $result = new static();

        return $result->addElements($elements);
    }
}
