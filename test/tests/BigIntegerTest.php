<?php

namespace Ocsp\Test;

use Ocsp\Asn1\Der\Decoder;
use Ocsp\Asn1\Der\Encoder;
use Ocsp\Asn1\Element\Integer;
use Ocsp\Asn1\Element\ObjectIdentifier;
use Ocsp\Service\Math;
use PHPUnit\Framework\TestCase;

class BigIntegerTest extends TestCase
{
    public function testDetectsNewestInstalledBigIntegerClass()
    {
        $expectedClass = 'phpseclib\Math\BigInteger';
        foreach (['phpseclib4\Math\BigInteger', 'phpseclib3\Math\BigInteger'] as $className) {
            if (class_exists($className)) {
                $expectedClass = $className;
                break;
            }
        }

        $this->assertSame($expectedClass, Math::getBigIntegerClass());
    }

    /**
     * @return array[]
     */
    public function largeIntegerProvider()
    {
        return [
            ['123456789012345678901234567890'],
            ['-123456789012345678901234567890'],
        ];
    }

    /**
     * @dataProvider largeIntegerProvider
     *
     * @param string $value
     */
    public function testLargeIntegerRoundTrip($value)
    {
        $encoder = new Encoder();
        $decoder = new Decoder();

        $decoded = $decoder->decodeElement($encoder->encodeElement(Integer::create($value)));

        $this->assertInstanceOf(Integer::class, $decoded);
        $this->assertInstanceOf(Math::getBigIntegerClass(), $decoded->getValue());
        $this->assertSame($value, $decoded->getValue()->toString());
    }

    public function testObjectIdentifierWithLargeArcRoundTrip()
    {
        $identifier = '2.25.329800735698586629295641978511506172918';
        $encoder = new Encoder();
        $decoder = new Decoder();

        $decoded = $decoder->decodeElement($encoder->encodeElement(ObjectIdentifier::create($identifier)));

        $this->assertInstanceOf(ObjectIdentifier::class, $decoded);
        $this->assertSame($identifier, $decoded->getIdentifier());
    }
}
