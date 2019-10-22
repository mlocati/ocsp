<?php

namespace Ocsp;

use DateTimeImmutable;

/**
 * Contains the response about the revocation of a certificate.
 */
class Response
{
    /**
     * Certificate revocation reason: unspecified.
     *
     * @var int
     */
    const REVOCATIONREASON_UNSPECIFIED = 0;

    /**
     * Certificate revocation reason: key compromise.
     *
     * @var int
     */
    const REVOCATIONREASON_KEYCOMPROMISE = 1;
    
    /**
     * Certificate revocation reason: CA Compromise.
     *
     * @var int
     */
    const REVOCATIONREASON_CACOMPROMISE = 2;
    
    /**
     * Certificate revocation reason: affiliation changed.
     *
     * @var int
     */
    const REVOCATIONREASON_AFFILIATIONCHANGED = 3;
    
    /**
     * Certificate revocation reason: superseded.
     *
     * @var int
     */
    const REVOCATIONREASON_SUPERSEDED = 4;
    
    /**
     * Certificate revocation reason: cessation of operation.
     *
     * @var int
     */
    const REVOCATIONREASON_CESSATIONOFOPERATION = 5;
    
    /**
     * Certificate revocation reason: certificate hold.
     *
     * @var int
     */
    const REVOCATIONREASON_CERTIFICATEHOLD = 6;
    
    /**
     * Certificate revocation reason: remove from CRL.
     *
     * @var int
     */
    const REVOCATIONREASON_REMOVEFROMCRL = 8;
    
    /**
     * Certificate revocation reason: privilege withdrawn.
     *
     * @var int
     */
    const REVOCATIONREASON_PRIVILEGEWITHDRAWN = 9;
    
    /**
     * Certificate revocation reason: AA compromise.
     *
     * @var int
     */
    const REVOCATIONREASON_AACOMPROMISE = 10;
    
    /**
     * The most recent time at which the status being indicated is known by the responder to have been correct.
     *
     * @var \DateTimeImmutable
     */
    private $thisUpdate;

    /**
     * The serial number of the certificate.
     *
     * @var string
     */
    private $certificateSerialNumber;

    /**
     * Is the certificate revoked (NULL: unknown)?
     *
     * @var bool|null
     */
    private $revoked;

    /**
     * The date/time when the revocation occurred.
     *
     * @var \DateTimeImmutable|null
     */
    private $revokedOn;

    /**
     * The revocation reason (if revoked).
     *
     * @var int|null
     */
    private $revocationReason;

    /**
     * @param \DateTimeImmutable $thisUpdate
     * @param string $certificateSerialNumber
     */
    protected function __construct(DateTimeImmutable $thisUpdate, $certificateSerialNumber)
    {
        $this->thisUpdate = $thisUpdate;
        $this->certificateSerialNumber = $certificateSerialNumber;
    }

    /**
     * Create a new instance when the certificate is good.
     *
     * @param \DateTimeImmutable $thisUpdate
     * @param string $certificateSerialNumber
     *
     * @return static
     */
    public static function good(DateTimeImmutable $thisUpdate, $certificateSerialNumber)
    {
        $result = new static($thisUpdate, $certificateSerialNumber);
        $result->revoked = false;

        return $result;
    }

    /**
     * Create a new instance when the certificate is revoked.
     *
     * @param \DateTimeImmutable $thisUpdate
     * @param string $certificateSerialNumber
     * @param \DateTimeImmutable $revokedOn
     *
     * @return static
     */
    public static function revoked(DateTimeImmutable $thisUpdate, $certificateSerialNumber, DateTimeImmutable $revokedOn, $revocationReason = self::REVOCATIONREASON_UNSPECIFIED)
    {
        $result = new static($thisUpdate, $certificateSerialNumber);
        $result->revoked = true;
        $result->revokedOn = $revokedOn;
        $result->revocationReason = (int) $revocationReason;

        return $result;
    }

    /**
     * Create a new instance when the certificate revocation is unknown.
     *
     * @param \DateTimeImmutable $thisUpdate
     * @param string $certificateSerialNumber
     *
     * @return static
     */
    public static function unknown(DateTimeImmutable $thisUpdate, $certificateSerialNumber)
    {
        $result = new static($thisUpdate, $certificateSerialNumber);

        return $result;
    }

    /**
     * Get the most recent time at which the status being indicated is known by the responder to have been correct.
     *
     * @return \DateTimeImmutable
     */
    public function getThisUpdate()
    {
        return $this->thisUpdate;
    }

    /**
     * Get the serial number of the certificate.
     *
     * @return string
     */
    public function getCertificateSerialNumber()
    {
        return $this->certificateSerialNumber;
    }

    /**
     * Is the certificate revoked (NULL: unknown)?
     *
     * @return bool|null
     */
    public function isRevoked()
    {
        return $this->revoked;
    }

    /**
     * Get the revocation date/time (not null only if the certificate is revoked).
     *
     * @return \DateTimeImmutable|null
     */
    public function getRevokedOn()
    {
        return $this->revokedOn;
    }

    /**
     * Get the revocation reason (if revoked).
     *
     * @return int|null
     */
    public function getRevocationReason()
    {
        return $this->revocationReason;
    }
}
