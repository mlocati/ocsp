<?php

/**
 * Taken from https://github.com/sop/asn1 MIT License Copyright (c) 2016-2021 Joni Eskelinen
 */

namespace Ocsp\Asn1;

use Ocsp\Asn1\TaggableElement;

/**
 * Base class for all string types.
 */
abstract class BaseString extends TaggableElement
{
    /**
     * String value.
     *
     * @var string
     */
    protected $string;

    /**
     * Constructor.
	 * 
	 * @param string  $string
     *
     * @throws \InvalidArgumentException
     */
    public function __construct( $string )
    {
		$this->setValue( $string );
    }

    /**
	 * Retrieve the value
     * @return string
     */
    public function getValue()
    {
        return $this->string;
    }

	/**
	 * Set and validate the value
     * @param string
     *
     * @return $this
     */
    public function setValue( $string )
    {
        if ( ! $this->validateString( $string ) )
		{
            throw new \InvalidArgumentException( sprintf('Not a valid %s string.', static::class ));
        }
        $this->string = $string;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function __toString(): string
    {
        return $this->string();
    }

    /**
     * Get the string value.
     */
    public function string(): string
    {
        return $this->string;
    }

    /**
     * Check whether string is valid for the concrete type.
     */
    protected function validateString( $string )
    {
        // Override in derived classes
        return true;
    }
}