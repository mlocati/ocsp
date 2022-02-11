<?php

namespace Ocsp\Asn1;

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
     * @var int|string|\Ocsp\BigInteger
     */
    private $tagID;

    /**
     * The class (the value of one of the Element::CLASS_... constants).
     *
     * @var string
     */
    private $class;

    /**
     * Create a new instante.
     *
     * @param string $environment the tag envoronment (the value of one of the Tag::ENVIRONMENT_... class constants)
     * @param int|string|\Ocsp\BigInteger $tagID the tag ID
     * @param string $class the class (the value of one of the Element::CLASS_... constants)
     */
    protected function __construct($environment, $tagID, $class)
    {
        $this->environment = $environment;
        $this->tagID = $tagID;
        $this->class = $class;
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
     * @return int|string|\Ocsp\BigInteger
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
     * Create a new IMPLICIT tag.
     *
     * @param int|string|\Ocsp\BigInteger $tagID the tag ID
     * @param string $class the class (the value of one of the Element::CLASS_... constants)
     *
     * @return static
     */
    public static function implicit($tagID, $class = Element::CLASS_CONTEXTSPECIFIC)
    {
        return new static(static::ENVIRONMENT_IMPLICIT, $tagID, $class);
    }

    /**
     * Create a new EXPLICIT tag.
     *
     * @param int|string|\Ocsp\BigInteger $tagID the tag ID
     * @param string $class the class (the value of one of the Element::CLASS_... constants)
     *
     * @return static
     */
    public static function explicit($tagID, $class = Element::CLASS_CONTEXTSPECIFIC)
    {
        return new static(static::ENVIRONMENT_EXPLICIT, $tagID, $class);
    }
}
