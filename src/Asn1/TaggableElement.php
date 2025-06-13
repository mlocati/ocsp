<?php

namespace Ocsp\Asn1;

/**
 * Interface that any ASN.1 element that can be tagged must implement.
 */
interface TaggableElement extends Element
{
    /**
     * Get the applied tag (if any).
     *
     * @var \Ocsp\Asn1\Tag|null
     */
    public function getTag();

    /**
     * Apply a tag.
     *
     * @param \Ocsp\Asn1\Tag|null $value
     *
     * @return $this
     */
    public function setTag(?Tag $value = null);
}
