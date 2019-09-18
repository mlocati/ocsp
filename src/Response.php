<?php

namespace Ocsp;

use DateTimeImmutable;

/**
 * Contains the response about the revocation of a certificate.
 */
class Response
{
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
    public static function revoked(DateTimeImmutable $thisUpdate, $certificateSerialNumber, DateTimeImmutable $revokedOn)
    {
        $result = new static($thisUpdate, $certificateSerialNumber);
        $result->revoked = true;
        $result->revokedOn = $revokedOn;

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
}
