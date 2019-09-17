<?php

namespace Ocsp\Asn1;

/**
 * Handy trait for classes that implements TaggableElement.
 */
trait TaggableElementTrait
{
    /**
     * The applied tag (if any).
     *
     * @var \Ocsp\Asn1\Tag|null
     */
    private $tag;

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
