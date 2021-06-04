<?php

/**
 * Taken from https://github.com/sop/asn1 MIT License Copyright (c) 2016-2021 Joni Eskelinen
 */

namespace Ocsp\Asn1\Element;

use Ocsp\Asn1\UniversalTagID;
use Ocsp\Asn1\PrimitiveString;

/**
 * Implements *IA5String* type.
 *
 * *IA5String* is used to represent ISO 646 (IA5) characters.
 */
class IA5String extends PrimitiveString
{
	/**
     * Create a new instance.
     *
     * @param string $value
     *
     * @return static
     */
    public static function create( $value )
    {
        return new static( $value );
    }

	public function getTypeID()
	{
		return UniversalTagID::IA5STRING;
	}

    /**
     * {@inheritdoc}
     */
    protected function validateString( $string )
    {
        return 0 == preg_match('/[^\x01-\x7f]/', $string);
    }
}