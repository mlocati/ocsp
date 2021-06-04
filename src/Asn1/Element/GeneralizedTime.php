<?php

namespace Ocsp\Asn1\Element;

use DateTimeImmutable;
use Ocsp\Asn1\Element;
use Ocsp\Asn1\Encoder;
use Ocsp\Asn1\TaggableElement;
use Ocsp\Asn1\UniversalTagID;
use Ocsp\Exception\Asn1DecodingException;

/**
 * ASN.1 element: GENERALIZEDTIME.
 */
class GeneralizedTime extends TaggableElement
{
    /**
     * @var \DateTimeImmutable
     */
    private $value;

    /**
     * Decode the value of a GeneralizedTime element.
     *
     * @param string $bytes
     *
     * @throws \Ocsp\Exception\Asn1DecodingException
     *
     * @return \DateTimeImmutable
     */
    public static function decodeGeneralizedTime( $bytes )
    {
        $matches = null;
        if (!preg_match('/(\d{4}\d{2}\d{2}\d{2}\d{2}\d{2})(?:\.(\d*))?Z$/', $bytes, $matches)) {
            throw Asn1DecodingException::create();
        }
        $dateTime = DateTimeImmutable::createFromFormat('!YmdHis.uT', $matches[1] . '.' . (isset($matches[2]) ? $matches[2] : '0') . 'UTC', new \DateTimeZone('UTC'));
        $result = $dateTime->setTimezone( new \DateTimeZone( \date_default_timezone_get() ) );

        return $result;
    }

    /**
     * Create a new instance.
     *
     * @param \DateTimeImmutable $value
     *
     * @return static
     */
    public static function create( $value )
    {
        $result = new static();

        return $result->setValue( $value );
    }

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
     * @see \Ocsp\Asn1\Element::getTypeID()
     */
    public function getTypeID()
    {
        return UniversalTagID::GENERALIZEDTIME;
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
     * @return \DateTimeImmutable
     */
    public function getValue()
    {
        return $this->value;
    }

    /**
     * @param \DateTimeImmutable $value
     *
     * @return $this
     */
    public function setValue( DateTimeImmutable $value )
    {
        $this->value = $value;

        return $this;
    }

    /**
     * {@inheritdoc}
     *
     * @see \Ocsp\Asn1\Element::getEncodedValue()
     */
    public function getEncodedValue( Encoder $encoder )
    {
        return $encoder->encodeGeneralizedTime( $this->getValue() );
    }
}
