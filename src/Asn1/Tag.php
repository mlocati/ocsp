<?php

namespace Ocsp\Asn1;

use Ocsp\Asn1\Util\BigInteger;

/**
 * Class used to tag ASN.1 elements.
 */
class Tag
{
    /**
     * Tag environment: IMPLICIT.
     *
     * @var string
     */
    const ENVIRONMENT_IMPLICIT = 'IMPLICIT';

    /**
     * Tag environment: EXPLICIT.
     *
     * @var string
     */
    const ENVIRONMENT_EXPLICIT = 'EXPLICIT';

    /**
     * The tag envoronment (the value of one of the Tag::ENVIRONMENT_... class constants).
     *
     * @var string
     */
    private $environment;

    /**
     * The tag ID.
     *
     * @var int|string|BigInteger
     */
    private $tagID;

    /**
     * The class (the value of one of the Element::CLASS_... constants).
     *
     * @var string
     */
    private $class;

    /**
     * When null the element's value will be used
     *
     * @var boolean
     */
    private $constructed = null;

    /**
     * Create a new instance.
     *
     * @param string $environment the tag envoronment (the value of one of the Tag::ENVIRONMENT_... class constants)
     * @param int|string|BigInteger $tagID the tag ID
     * @param string $class the class (the value of one of the Element::CLASS_... constants)
     * @param bool $isConstructed (default null) true or false
     */
    protected function __construct($environment, $tagID, $class, $isConstructed = null )
    {
        $this->environment = $environment;
        $this->tagID = $tagID;
        $this->class = $class;
        $this->constructed = $isConstructed;
    }

    /**
     * Get the tag envoronment (the value of one of the Tag::ENVIRONMENT_... class constants).
     *
     * @return string
     */
    public function getEnvironment()
    {
        return $this->environment;
    }

    /**
     * Get the tag ID.
     *
     * @return int|string|BigInteger
     */
    public function getTagID()
    {
        return $this->tagID;
    }

    /**
     * Get the class (the value of one of the Element::CLASS_... constants).
     *
     * @return string
     */
    public function getClass()
    {
        return $this->class;
    }

    /**
     * Returns the constructed state for the tag
     *
     * @return boolean
     */
    public function isConstructed()
    {
        return $this->constructed;
    }

    /**
     * Create a new IMPLICIT tag.  An implicit tag has the effect of changing the id of the 
     * element to which it is attached and, usually sets the class to context specific. 
     * This technique is used often in CRL documents.
     *
     * @param int|string|BigInteger $tagID the tag ID
     * @param string $class the class (the value of one of the Element::CLASS_... constants)
     * @param bool $isConstructed (default null) True or false
     *
     * @return static
     */
    public static function implicit( $tagID, $class = Element::CLASS_CONTEXTSPECIFIC, $isConstructed = null )
    {
        return new static(static::ENVIRONMENT_IMPLICIT, $tagID, $class, $isConstructed );
    }

    /**
     * Create a new EXPLICIT tag. An explicit tag add two extra bytes to the encoded document
     * so the original element code remains the same but an application can find and use the
     * element in a context specific way.
     *
     * @param int|string|BigInteger $tagID the tag ID
     * @param string $class the class (the value of one of the Element::CLASS_... constants)
     * @param bool $isConstructed (default null) True or false
     *
     * @return static
     */
    public static function explicit( $tagID, $class = Element::CLASS_CONTEXTSPECIFIC, $isConstructed = null )
    {
        return new static(static::ENVIRONMENT_EXPLICIT, $tagID, $class, $isConstructed);
    }
}
