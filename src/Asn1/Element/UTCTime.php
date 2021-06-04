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
class UTCTime extends TaggableElement
{
    /**
	 * UTC timezone.
	 * @var string
	 */
	const TZ_UTC = 'UTC';

    /**
     * @var \DateTimeImmutable
     */
    private $value;

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
        return UniversalTagID::UTCTIME;
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
        $this->value = $value->setTimezone( self::createTimeZone( UTCTime::TZ_UTC ) );

        return $this;
    }

    /**
     * {@inheritdoc}
     *
     * @see \Ocsp\Asn1\Element::getEncodedValue()
     */
    public function getEncodedValue( Encoder $encoder )
    {
        return $encoder->encodeUTCTime( $this->getValue() );
    }

    /**
     * Decode the value of a UTCTime element.
     *
     * @param string $bytes
     *
     * @return \DateTimeImmutable
     */
    public static function decodeUTCTime( $bytes )
    {
		/**
		 * Regular expression to parse date.
		 * @var string
		 */
		$REGEX = '#^' .
			'(\d\d)' . // YY
			'(\d\d)' . // MM
			'(\d\d)' . // DD
			'(\d\d)' . // hh
			'(\d\d)' . // mm
			'(\d\d)' . // ss
			'Z' . // TZ
			'$#';

        /** @var string[] $match */
        if ( ! preg_match( $REGEX, $bytes, $match ) )
		{
            throw Asn1DecodingException::create('Invalid UTCTime format.');
        }
        [, $year, $month, $day, $hour, $minute, $second] = $match;
        $time = $year . $month . $day . $hour . $minute . $second . UTCTime::TZ_UTC;
        $dt = \DateTimeImmutable::createFromFormat( '!ymdHisT', $time, self::createTimeZone( UTCTime::TZ_UTC ) );
        if ( ! $dt )
		{
            throw Asn1DecodingException::create('Failed to decode UTCTime: ' . self::getLastDateTimeImmutableErrorsStr());
        }

        return $dt;
    }

    /**
     * Create `DateTimeZone` object from string.
     *
     * @throws \UnexpectedValueException If timezone is invalid
     */
    public static function createTimeZone(string $tz): \DateTimeZone
    {
        try {
            return new \DateTimeZone($tz);
        } catch (\Exception $e) {
            throw new \UnexpectedValueException('Invalid timezone.', 0, $e);
        }
    }

    /**
     * Get last error caused by `DateTimeImmutable`.
     */
    public static function getLastDateTimeImmutableErrorsStr(): string
    {
        $errors = \DateTimeImmutable::getLastErrors()['errors'];
        return implode(', ', $errors);
    }
}
