<?php

namespace Ocsp\Asn1\Element;

use Ocsp\Asn1\Element;
use Ocsp\Asn1\Util\BigInteger;
use Ocsp\Asn1\Encoder;
use Ocsp\Asn1\TaggableElement;

/**
 * Base handy class for CONSTRUCTED ASN.1 elements.
 */
abstract class AbstractList extends TaggableElement
{
    /**
     * The child elements.
     *
     * @var \Ocsp\Asn1\Element[]
     */
    private $elements = [];

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
        return true;
    }

    /**
     * Get the child elements.
     *
     * @return \Ocsp\Asn1\Element[]
     */
    public function getElements()
    {
        return $this->elements;
    }

    /**
     * Add a new child element.
     *
     * @param \Ocsp\Asn1\Element $element
     *
     * @return $this
     */
    public function addElement(Element $element)
    {
        $this->elements[] = $element;

        return $this;
    }

    /**
     * Add child elements.
     *
     * @param \Ocsp\Asn1\Element[] $elements
     *
     * @return $this
     */
    public function addElements(array $elements)
    {
        foreach ($elements as $element) {
            $this->addElement($element);
        }

        return $this;
    }

    /**
     * {@inheritdoc}
     *
     * @see \Ocsp\Asn1\Element::getEncodedValue()
     */
    public function getEncodedValue(Encoder $encoder)
    {
        $elementBytes = [];
        foreach ($this->getElements() as $element) {
            $elementBytes[] = $encoder->encodeElement($element);
        }

        return implode('', $elementBytes);
    }

    /**
     * Shorthand function to get the first element of any type
     *
     * @return TaggableElement
     */
    public function first()
    {
        return $this->at( 1 );
    }

    /**
     * Find the first child of a specific type.
     *
     * @param int|string|BigInteger $typeID
     * @param string $class
     * @param string $tagEnvironment
     *
     * @return Element
     */
    public function getFirstChildOfType( $typeID, $class = Element::CLASS_UNIVERSAL, $tagEnvironment = '' )
    {
        return $this->getNthChildOfType( 1, $typeID, $class, $tagEnvironment);
    }

    /**
     * Shorthand function to get the element of any type at some position
     *
     * @param int $position
     * @return TaggableElement
     */
    public function at( $position )
    {
        return $this->getNthChildOfType( $position, null );
    }

    /**
     * Find the Nth child of a specific type.
     *
     * @param int $position
     * @param int|string|BigInteger $typeID
     * @param string $class
     * @param string $tagEnvironment
     *
     * @return Element
     */
    public function getNthChildOfType($position, $typeID, $class = Element::CLASS_UNIVERSAL, $tagEnvironment = '')
    {
        $typeIDString = (string) $typeID;
        $found = 0;
        foreach ($this->getElements() as $element) 
        {
            if ( ! is_null( $typeID ) )
            {
                $tag = $element instanceof TaggableElement ? $element->getTag() : null;
                $actualTypeIDString = (string) ($tag === null ? $element->getTypeID() : $tag->getTagID());
                if ($actualTypeIDString !== $typeIDString)
                {
                    continue;
                }

                $actualClass = $tag === null ? $element->getClass() : $tag->getClass();
                if ($actualClass !== $class)
                {
                    continue;
                }

                if ($tagEnvironment === '')
                {
                    if ($tag !== null) 
                    {
                        continue;
                    }
                } else 
                {
                    if ($tag === null || $tag->getEnvironment() !== $tagEnvironment) {
                        continue;
                    }
                }
            }

            ++$found;

            if ($found === $position)
            {
                return $element;
            }
        }

        return null;
    }

    /**
     * Find the Nth child of an untagged element with a specific class.
     *
     * @param int $position
     * @param string $class
     *
     * @return \Ocsp\Asn1\Element|null
     */
    public function getNthUntaggedChild($position, $class)
    {
        $found = 0;
        foreach ($this->getElements() as $element) {
            if ($element instanceof TaggableElement) {
                if ($element->getTag() !== null) {
                    continue;
                }
            }
            if ($element->getClass() !== $class) {
                continue;
            }
            ++$found;
            if ($found === $position) {
                return $element;
            }
        }

        return null;
    }
}
