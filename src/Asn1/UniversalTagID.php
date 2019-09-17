<?php

namespace Ocsp\Asn1;

/**
 * List of tag IDs in the UNIVERSAL class.
 */
class UniversalTagID
{
    /**
     * Universal tag ID: BOOLEAN.
     *
     * @var int
     */
    const BOOLEAN = 1;

    /**
     * Universal tag ID: INTEGER.
     *
     * @var int
     */
    const INTEGER = 2;

    /**
     * Universal tag ID: BIT STRING.
     *
     * @var int
     */
    const BIT_STRING = 3;

    /**
     * Universal tag ID: OCTET STRING.
     *
     * @var int
     */
    const OCTET_STRING = 4;

    /**
     * Universal tag ID: NULL.
     *
     * @var int
     */
    const NULL = 5;

    /**
     * Universal tag ID: OBJECT IDENTIFIER.
     *
     * @var int
     */
    const OBJECT_IDENTIFIER = 6;

    /**
     * Universal tag ID: ObjectDescriptor.
     *
     * @var int
     */
    const OBJECTDESCRIPTOR = 7;

    /**
     * Universal tag ID: INSTANCE OF / EXTERNAL.
     *
     * @var int
     */
    const INSTANCE_OF__EXTERNAL = 8;

    /**
     * Universal tag ID: REAL.
     *
     * @var int
     */
    const REAL = 9;

    /**
     * Universal tag ID: ENUMERATED.
     *
     * @var int
     */
    const ENUMERATED = 10;

    /**
     * Universal tag ID: EMBEDDED PDV.
     *
     * @var int
     */
    const EMBEDDED_PDV = 11;

    /**
     * Universal tag ID: UTF8String.
     *
     * @var int
     */
    const UTF8STRING = 12;

    /**
     * Universal tag ID: RELATIVE-OID.
     *
     * @var int
     */
    const RELATIVE_OID = 13;

    /**
     * Universal tag ID: SEQUENCE / SEQUENCE OF.
     *
     * @var int
     */
    const SEQUENCE = 16;

    /**
     * Universal tag ID: SET / SET OF.
     *
     * @var int
     */
    const SET = 17;

    /**
     * Universal tag ID: NumericString.
     *
     * @var int
     */
    const NUMERICSTRING = 18;

    /**
     * Universal tag ID: PrintableString.
     *
     * @var int
     */
    const PRINTABLESTRING = 19;

    /**
     * Universal tag ID: TeletexString / T61String.
     *
     * @var int
     */
    const TELETEXSTRING = 20;

    /**
     * Universal tag ID: VideotexString.
     *
     * @var int
     */
    const VIDEOTEXSTRING = 21;

    /**
     * Universal tag ID: IA5String.
     *
     * @var int
     */
    const IA5STRING = 22;

    /**
     * Universal tag ID: UTCTime.
     *
     * @var int
     */
    const UTCTIME = 23;

    /**
     * Universal tag ID: GeneralizedTime.
     *
     * @var int
     */
    const GENERALIZEDTIME = 24;

    /**
     * Universal tag ID: GraphicString.
     *
     * @var int
     */
    const GRAPHICSTRING = 25;

    /**
     * Universal tag ID: VisibleString / ISO646String.
     *
     * @var int
     */
    const VISIBLESTRING = 26;

    /**
     * Universal tag ID: GeneralString.
     *
     * @var int
     */
    const GENERALSTRING = 27;

    /**
     * Universal tag ID: UniversalString.
     *
     * @var int
     */
    const UNIVERSALSTRING = 28;

    /**
     * Universal tag ID: CHARACTER STRING.
     *
     * @var int
     */
    const CHARACTER_STRING = 29;

    /**
     * Universal tag ID: BMPString.
     *
     * @var int
     */
    const BMPSTRING = 30;
}
