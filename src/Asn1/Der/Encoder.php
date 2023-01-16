<?php

namespace Ocsp\Asn1\Der;

use DateTime;
use DateTimeImmutable;
use DateTimeZone;
use Ocsp\Asn1\Element;
use Ocsp\Asn1\Encoder as EncoderInterface;
use Ocsp\Asn1\Tag;
use Ocsp\Asn1\TaggableElement;
use Ocsp\Exception\Asn1EncodingException;
use Ocsp\Service\Math;

/**
 * Encoder from ASN.1 to DER.
 */
class Encoder implements EncoderInterface
{
    /**
     * {@inheritdoc}
     *
     * @see \Ocsp\Asn1\Encoder::getEncodingHandle()
     */
    public function getEncodingHandle()
    {
        return 'der';
    }

    /**
     * {@inheritdoc}
     *
     * @see \Ocsp\Asn1\Encoder::encodeElement()
     */
    public function encodeElement(Element $element)
    {
        $tag = null;
        if ($element instanceof TaggableElement) {
            $tag = $element->getTag();
        }
        if ($tag === null) {
            return $this->doEncodeElement($element);
        }
        switch ($tag->getEnvironment()) {
            case Tag::ENVIRONMENT_EXPLICIT:
                $elementBytes = $this->doEncodeElement($element);

                return $this->encodeType($tag->getTagID(), $tag->getClass(), true) . $this->encodeLength($elementBytes) . $elementBytes;
            case Tag::ENVIRONMENT_IMPLICIT:
                return $this->doEncodeElement($element, $tag);
            default:
                throw Asn1EncodingException::create(sprintf('Invalid ASN.1 tag environment: %s', $tag->getEnvironment()));
        }
    }

    /**
     * {@inheritdoc}
     *
     * @see \Ocsp\Asn1\Encoder::encodeInteger()
     */
    public function encodeInteger($value)
    {
        if (is_int($value)) {
            if ($value === 0) {
                return "\x00";
            }
            if ($value > 0) {
                if (PHP_INT_SIZE === 4 || $value < 0xFFFFFFFF) {
                    return ltrim(pack('N', $value), "\x00");
                }
                if (PHP_VERSION_ID >= 50603) {
                    return ltrim(pack('J', $value), "\x00");
                }
            }
            $value = Math::createBigInteger((string) $value);
        } elseif (is_string($value)) {
            $value = Math::createBigInteger($value);
        }

        return $value->toBytes(true);
    }

    /**
     * {@inheritdoc}
     *
     * @see \Ocsp\Asn1\Encoder::encodeIdentifier()
     */
    public function encodeIdentifier($value)
    {
        $parts = explode('.', $value);
        $result = chr((int) array_shift($parts) * 40 + (int) array_shift($parts));
        while (($part = array_shift($parts)) !== null) {
            $result .= $this->encodeIdentifierPart($part);
        }

        return $result;
    }

    /**
     * {@inheritdoc}
     *
     * @see \Ocsp\Asn1\Encoder::encodeOctetString()
     */
    public function encodeOctetString($value)
    {
        return $value;
    }

    /**
     * {@inheritdoc}
     *
     * @see \Ocsp\Asn1\Encoder::encodePrintableString()
     */
    public function encodePrintableString($value)
    {
        return $value;
    }

    /**
     * {@inheritdoc}
     *
     * @see \Ocsp\Asn1\Encoder::encodeBitString()
     */
    public function encodeBitString($bytes, $unusedBitsInLastByte)
    {
        return chr($unusedBitsInLastByte) . $bytes;
    }

    /**
     * {@inheritdoc}
     *
     * @see \Ocsp\Asn1\Encoder::encodeGeneralizedTime()
     */
    public function encodeGeneralizedTime(DateTimeImmutable $value)
    {
        $datetime = new DateTime('now', new DateTimeZone('UTC'));
        $datetime->setTimestamp($value->getTimestamp());

        $result = $datetime->format('YmdHis');
        $useconds = ltrim($value->format('u'), '0');
        if ($useconds !== '') {
            $result .= '.' . $useconds;
        }
        $result .= 'Z';

        return $result;
    }

    /**
     * @param \Ocsp\Asn1\Element $element
     * @param \Ocsp\Asn1\Tag|null $implicitTag
     *
     * @throws \Ocsp\Exception\Asn1EncodingException when the element or the tag are defined in invalid classes
     *
     * @return string
     */
    protected function doEncodeElement(Element $element, Tag $implicitTag = null)
    {
        if ($implicitTag === null) {
            $result = $this->encodeType($element->getTypeID(), $element->getClass(), $element->isConstructed());
        } else {
            $result = $this->encodeType($implicitTag->getTagID(), $implicitTag->getClass(), $element->isConstructed());
        }
        $elementBytes = $element->getEncodedValue($this);

        return $result . $this->encodeLength($elementBytes) . $elementBytes;
    }

    /**
     * Encode a part of the value of an IDENTIFIER element.
     *
     * @param string $part
     *
     * @return string
     */
    protected function encodeIdentifierPart($part)
    {
        $part = ltrim($part, '0');
        if ($part === '') {
            return "\x00";
        }
        $bytes = [];
        if (strlen($part) < strlen(PHP_INT_MAX)) {
            $int = (int) $part;
            if ($int <= 127) {
                return chr($int);
            }
            $bits = decbin($int);
        } else {
            $bits = Math::createBigInteger($part)->toBits();
        }
        do {
            array_unshift($bytes, bindec(substr($bits, -7)));
            $bits = substr($bits, 0, -7);
        } while ($bits !== '' && $bits !== false);
        $result = '';
        foreach (array_splice($bytes, 0, -1) as $byte) {
            $result .= chr(0x80 | $byte);
        }
        $result .= chr(reset($bytes));

        return $result;
    }

    /**
     * Encode the type ID.
     *
     * @param int|string|\phpseclib\Math\BigInteger|\phpseclib3\Math\BigInteger $typeID the type ID
     * @param string $class the class (the value of one of the Element::CLASS_... constants)
     * @param bool $isConstructed is the element a constructed element?
     *
     * @throws \Ocsp\Exception\Asn1EncodingException when $class contains an invalid value
     *
     * @return string
     */
    protected function encodeType($typeID, $class, $isConstructed)
    {
        switch ($class) {
            case Element::CLASS_UNIVERSAL:
                $firstByte = 0b00000000;
                break;
            case Element::CLASS_APPLICATION:
                $firstByte = 0b01000000;
                break;
            case Element::CLASS_CONTEXTSPECIFIC:
                $firstByte = 0b10000000;
                break;
            case Element::CLASS_PRIVATE:
                $firstByte = 0b11000000;
                break;
            default:
                throw Asn1EncodingException::create(sprintf('Invalid ASN.1 class: %s', $class));
        }
        if ($isConstructed) {
            $firstByte |= 0b00100000;
        }
        $typeIDBits = $this->getBits($typeID);
        if (!isset($typeIDBits[5])) {
            $typeIDInt = bindec($typeIDBits);
            if ($typeIDInt <= 30) {
                return chr($firstByte | $typeIDInt);
            }
        }
        $result = chr($firstByte | 0b00011111);
        while (isset($typeIDBits[7])) {
            $result .= chr(bindec('1' . substr($typeIDBits, -7)));
            $typeIDBits = substr($typeIDBits, 0, -7);
        }
        $result .= chr(bindec($typeIDBits));

        return $result;
    }

    /**
     * Encode the length of the encoded value of an element.
     *
     * @param string $encodedElementValue the encoded value of an element
     *
     * @return string
     */
    protected function encodeLength($encodedElementValue)
    {
        $length = strlen($encodedElementValue);
        if ($length < 127) {
            return chr($length);
        }
        $lengthHex = dechex($length);
        $lengthHexLength = strlen($lengthHex);
        if (($lengthHexLength % 2) !== 0) {
            $lengthHex = '0' . $lengthHex;
            $lengthHexLength++;
        }
        $lengthNumBytes = strlen($lengthHex) >> 1;
        $result = chr($lengthNumBytes | 0x80);
        for ($index = 0; $index < $lengthHexLength; $index += 2) {
            $result .= chr(hexdec($lengthHex[$index] . $lengthHex[$index + 1]));
        }

        return $result;
    }

    /**
     * Get the bits representing a number.
     *
     * @param int|string|\phpseclib\Math\BigInteger|\phpseclib3\Math\BigInteger $number
     *
     * @return string
     */
    protected function getBits($number)
    {
        if (is_int($number)) {
            return decbin($number);
        }
        if (is_string($number)) {
            $number = ltrim($number, '0');
            if ($number === '') {
                return '0';
            }
            if (strlen($number) < strlen((string) PHP_INT_MAX)) {
                return decbin((int) $number);
            }
            $number = Math::createBigInteger($number);
        }

        return $number->toBits(true);
    }
}
