<?php

namespace Ocsp\Asn1\Der;

use DateTimeImmutable;
use DateTimeZone;
use Ocsp\Asn1\Decoder as DecoderInterface;
use Ocsp\Asn1\Element;
use Ocsp\Asn1\Element\BitString;
use Ocsp\Asn1\Element\GeneralizedTime;
use Ocsp\Asn1\Element\Integer;
use Ocsp\Asn1\Element\ObjectIdentifier;
use Ocsp\Asn1\Element\OctetString;
use Ocsp\Asn1\Element\PrintableString;
use Ocsp\Asn1\Element\RawConstructed;
use Ocsp\Asn1\Element\RawPrimitive;
use Ocsp\Asn1\Element\Sequence;
use Ocsp\Asn1\Element\Set;
use Ocsp\Asn1\Tag;
use Ocsp\Asn1\TaggableElement;
use Ocsp\Asn1\UniversalTagID;
use Ocsp\Exception\Asn1DecodingException;
use Ocsp\Service\Math;

/**
 * Decoder from DER to ASN.1.
 */
class Decoder implements DecoderInterface
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
     * @see \Ocsp\Asn1\Decoder::decodeElement()
     */
    public function decodeElement($bytes)
    {
        $offset = 0;

        return $this->decodeElementAt($bytes, $offset);
    }

    /**
     * Decode an element at a specific position in a range of bytes.
     *
     * @param string $bytes
     * @param int $offset
     *
     * @throws \Ocsp\Exception\Asn1DecodingException
     *
     * @return \Ocsp\Asn1\Element
     */
    protected function decodeElementAt($bytes, &$offset)
    {
        list($typeID, $class, $isConstructed) = $this->decodeType($bytes, $offset);
        $encodedValue = $this->extractEncodedValue($bytes, $offset);

        return $isConstructed ? $this->decodeConstructed($typeID, $class, $encodedValue) : $this->decodePrimitive($typeID, $class, $encodedValue);
    }

    /**
     * Decode a CONSTRUCTED ASN.1 element.
     *
     * @param int|\phpseclib\Math\BigInteger|\phpseclib3\Math\BigInteger $typeID
     * @param string $class
     * @param string $encodedValue
     *
     * @throws \Ocsp\Exception\Asn1DecodingException
     *
     * @return \Ocsp\Asn1\Element
     */
    protected function decodeConstructed($typeID, $class, $encodedValue)
    {
        $offset = 0;
        $encodedValueLength = strlen($encodedValue);
        $elements = [];
        while ($offset < $encodedValueLength) {
            if ($encodedValue[$offset] === "\x00" && isset($encodedValue[$offset + 1]) && $encodedValue[$offset + 1] === "\x00") {
                // end of elements in case the length is in indefinite form
                break;
            }
            $elements[] = $this->decodeElementAt($encodedValue, $offset);
        }
        if (count($elements) === 1 && $class !== Element::CLASS_UNIVERSAL && $elements[0] instanceof TaggableElement) {
            return $elements[0]->setTag(Tag::explicit($typeID, $class));
        }
        if (is_int($typeID) && $class === Element::CLASS_UNIVERSAL) {
            switch ($typeID) {
                case UniversalTagID::SEQUENCE:
                    return Sequence::create($elements);
                case UniversalTagID::SET:
                    return Set::create($elements);
            }
        }

        return RawConstructed::create($this->getEncodingHandle(), $typeID, $class, $elements);
    }

    /**
     * Decode a PRIMITIVE ASN.1 element.
     *
     * @param int $typeID
     * @param string $class
     * @param string $encodedValue
     *
     * @throws \Ocsp\Exception\Asn1DecodingException
     *
     * @return \Ocsp\Asn1\Element
     */
    protected function decodePrimitive($typeID, $class, $encodedValue)
    {
        if ($class === Element::CLASS_UNIVERSAL) {
            switch ($typeID) {
                case UniversalTagID::INTEGER:
                    return Integer::create($this->decodeInteger($encodedValue));
                case UniversalTagID::BIT_STRING:
                    list($bytes, $numTrailingBits) = $this->decodeBitString($encodedValue);

                    return BitString::create($bytes, $numTrailingBits);
                case UniversalTagID::OCTET_STRING:
                    return OctetString::create($this->decodeOctetString($encodedValue));
                case UniversalTagID::OBJECT_IDENTIFIER:
                    return ObjectIdentifier::create($this->decodeObjectIdentifier($encodedValue));
                case UniversalTagID::PRINTABLESTRING:
                    return PrintableString::create($this->decodePrintableString($encodedValue));
                case UniversalTagID::GENERALIZEDTIME:
                    return GeneralizedTime::create($this->decodeGeneralizedTime($encodedValue));
            }
        }

        return RawPrimitive::create($this->getEncodingHandle(), $typeID, $class, $encodedValue);
    }

    /**
     * Extract the details about at a specific position in a range of bytes.
     *
     * @param string $bytes
     * @param int $offset
     *
     * @throws \Ocsp\Exception\Asn1DecodingException
     *
     * @return array<int|\phpseclib\Math\BigInteger|\phpseclib3\Math\BigInteger, string, bool>
     */
    protected function decodeType($bytes, &$offset)
    {
        if (!isset($bytes[$offset])) {
            throw Asn1DecodingException::create();
        }
        $byte = ord($bytes[$offset++]);
        $isConstructed = ($byte & 0b100000) !== 0;
        if (($byte & 0b11000000) === 0b11000000) {
            $class = Element::CLASS_PRIVATE;
        } elseif ($byte & 0b10000000) {
            $class = Element::CLASS_CONTEXTSPECIFIC;
        } elseif ($byte & 0b01000000) {
            $class = Element::CLASS_APPLICATION;
        } else {
            $class = Element::CLASS_UNIVERSAL;
        }
        $typeID = $byte & 0b00011111;
        if ($typeID === 0b00011111) {
            $typeParts = [];
            do {
                if (!isset($bytes[$offset])) {
                    throw Asn1DecodingException::create();
                }
                $byte = ord($bytes[$offset++]);
                $typeParts[] = $byte & 0b01111111;
            } while (($byte & 0b10000000) === 0);
            $numTypeParts = count($typeParts);
            if ($numTypeParts > PHP_INT_SIZE || ($numTypeParts === PHP_INT_SIZE && $typeParts[$numTypeParts - 1] & 0b10000000)) {
                $typeIDBits = '';
                for ($i = 0; $i < $numTypeParts; $i++) {
                    $typeIDBits .= str_pad(decbin($typeParts[$i]), 7, '0', STR_PAD_LEFT);
                }
                $typeID = Math::createBigInteger($typeIDBits, 2);
            } else {
                $typeID = 0;
                for ($i = $numTypeParts - 1; $i >= 0; $i--) {
                    $typeID = ($typeID << 7) + $typeParts[$i];
                }
            }
        }

        return [$typeID, $class, $isConstructed];
    }

    /**
     * Extract the bytes representing the value of an element.
     *
     * @param string $bytes
     * @param int $offset
     *
     * @throws \Ocsp\Exception\Asn1DecodingException
     *
     * @return string
     */
    protected function extractEncodedValue($bytes, &$offset)
    {
        $length = $this->decodeLength($bytes, $offset);
        if ($length === 0) {
            return '';
        }
        if ($offset + $length > strlen($bytes)) {
            throw Asn1DecodingException::create();
        }
        $encodedValue = substr($bytes, $offset, $length);
        $offset += $length;

        return $encodedValue;
    }

    /**
     * Extract the length (in bytes) of the encoded value an element.
     *
     * @param string $bytes
     * @param int $offset
     *
     * @throws \Ocsp\Exception\Asn1DecodingException
     *
     * @return int
     */
    protected function decodeLength($bytes, &$offset)
    {
        if (!isset($bytes[$offset])) {
            throw Asn1DecodingException::create();
        }
        $byte = ord($bytes[$offset++]);
        if (($byte & 0b10000000) === 0) {
            // short form
            return $byte;
        }
        if ($byte === 0b10000000) {
            // indefinite form
            return strlen($bytes) - $offset;
        }
        // technically, the long form of the length can be represented by up to 126 octets (bytes), but we'll only
        // support it up to four.
        $numLenghtBytes = $byte & 0b01111111;
        if ($numLenghtBytes === 0) {
            throw Asn1DecodingException::create();
        }
        $length = 0;
        for ($i = 0; $i < $numLenghtBytes; $i++) {
            if (!isset($bytes[$offset])) {
                throw Asn1DecodingException::create();
            }
            $byte = ord($bytes[$offset++]);
            if ($i === PHP_INT_SIZE || ($i === PHP_INT_SIZE - 1 && $byte & 0b10000000)) {
                throw Asn1DecodingException::create('Element length too long for this implementation');
            }
            $length = ($length << 8) + $byte;
        }

        return $length;
    }

    /**
     * Decode the value of an INTEGER element.
     *
     * @param string $bytes
     *
     * @return int|\phpseclib\Math\BigInteger|\phpseclib3\Math\BigInteger
     */
    protected function decodeInteger($bytes)
    {
        $numBytes = strlen($bytes);
        $firstByte = ord($bytes[0]);
        $isNegative = ($firstByte & 0b10000000) !== 0;
        if ($isNegative === false) {
            switch ($numBytes) {
                case 1:
                    return $firstByte;
                case 2:
                    return current(unpack('n', $bytes));
                case 3:
                    return current(unpack('N', "\x00" . $bytes));
                case 4:
                    return current(unpack('N', $bytes));
            }
            if ($numBytes <= 8 && PHP_INT_SIZE >= 8 && PHP_VERSION_ID >= 50603) {
                return current(unpack('J', str_pad($bytes, 8, "\x00", STR_PAD_LEFT)));
            }
        }

        return Math::createBigInteger($bytes, -256);
    }

    /**
     * Decode the value of a BIT STRING element.
     *
     * @param string $bytes
     *
     * @return string
     */
    protected function decodeBitString($bytes)
    {
        $numTrailingBits = ord($bytes[0]) & 0b01111111;
        $bytes = substr($bytes, 1);
        if ($bytes === false) {
            $bytes = '';
        }

        return [$bytes, $numTrailingBits];
    }

    /**
     * Decode the value of a OCTET STRING element.
     *
     * @param string $bytes
     *
     * @return string
     */
    protected function decodeOctetString($bytes)
    {
        return $bytes;
    }

    /**
     * Decode the value of a OBJECT IDENTIFIER element.
     *
     * @param string $bytes
     *
     * @throws \Ocsp\Exception\Asn1DecodingException
     *
     * @return string
     */
    protected function decodeObjectIdentifier($bytes)
    {
        $byte = ord($bytes[0]);
        $result = sprintf('%d.%d', floor($byte / 40), $byte % 40);
        $len = strlen($bytes);
        $chunkBits = '';
        $maxIntBits = PHP_INT_SIZE * 8 - 1;
        for ($offset = 1; $offset < $len; $offset++) {
            $byte = ord($bytes[$offset]);
            $chunkBits .= str_pad(decbin($byte & 0b01111111), 7, '0', STR_PAD_LEFT);
            if (($byte & 0b10000000) === 0) {
                $result .= '.';
                if (strlen($chunkBits) <= $maxIntBits) {
                    $result .= (string) bindec($chunkBits);
                } else {
                    $result .= Math::createBigInteger($chunkBits, 2)->toString();
                }
                $chunkBits = '';
            }
        }
        if ($chunkBits !== '') {
            throw Asn1DecodingException::create();
        }

        return $result;
    }

    /**
     * Decode the value of a PrintableString element.
     *
     * @param string $bytes
     *
     * @return string
     */
    protected function decodePrintableString($bytes)
    {
        return $bytes;
    }

    /**
     * Decode the value of a GeneralizedTime element.
     *
     * @param string $bytes
     *
     * @throws \Ocsp\Exception\Asn1DecodingException
     *
     * @return \DateTimeImmutable
     */
    protected function decodeGeneralizedTime($bytes)
    {
        $matches = null;
        if (!preg_match('/(\d{4}\d{2}\d{2}\d{2}\d{2}\d{2})(?:\.(\d*))?Z$/', $bytes, $matches)) {
            throw Asn1DecodingException::create();
        }
        $dateTime = DateTimeImmutable::createFromFormat('!YmdHis.uT', $matches[1] . '.' . (isset($matches[2]) ? $matches[2] : '0') . 'UTC', new DateTimeZone('UTC'));
        $result = $dateTime->setTimezone(new DateTimeZone(date_default_timezone_get()));

        return $result;
    }
}
