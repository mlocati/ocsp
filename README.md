[![Tests](https://github.com/mlocati/ocsp/actions/workflows/tests.yml/badge.svg)](https://github.com/mlocati/ocsp/actions?query=workflow%3A%22tests%22)
[![Coverage Status](https://coveralls.io/repos/github/mlocati/ocsp/badge.svg?branch=main)](https://coveralls.io/github/mlocati/ocsp?branch=main)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/mlocati/ocsp/badges/quality-score.png?b=main)](https://scrutinizer-ci.com/g/mlocati/ocsp/?branch=main)
![Packagist Downloads](https://img.shields.io/packagist/dm/mlocati/ocsp)

# Online Certificate Status Protocol PHP Library

This repository contains a PHP library that helps you checking if HTTPS certificates are revoked, by using the Online Certificate Status Protocol (OCSP).

This library doesn't require `exec` calls to system utilities like OpenSSL: it's a pure PHP library.

This library doesn't include any network-related helpers: you have to use your own transport libraries (cURL, Zend HTTP, Guzzle or whatever).

Checking HTTPS certificates requires:

- the certificate to be checked, in PEM format (that is, the text files that starts with `-----BEGIN CERTIFICATE-----), or in DER format (that is, binary files)
- the issuer certificate, that is the certificate of the Certification Authority that provided you the HTTPS certificate
- the URL, provided by the Certification Authority, to be used for OCSP calls (the so-called `OCSR Responder URL`)


## Obtaining the certificate and the issuer certificate from an HTTPS URL

You can get the HTTPS certificate and the issuer certificate from an HTTPS URL by using some code like this:

```php
$hCurl = curl_init($url);
curl_setopt($hCurl, CURLOPT_RETURNTRANSFER, false);
curl_setopt($hCurl, CURLOPT_CUSTOMREQUEST, 'HEAD');
curl_setopt($hCurl, CURLOPT_NOBODY, true);
curl_setopt($hCurl, CURLOPT_CERTINFO, true);
curl_exec($hCurl);
$certInfo = curl_getinfo($hCurl, CURLINFO_CERTINFO);

$certificate = $certInfo[0]['Cert'];
$issuerCertificate = $certInfo[1]['Cert'];
```

## Obtaining the issuer certificate from a certificate

HTTPS certificates usually contain an URL where you can find the certificate of the certificate issuer.

You can use this code to extract this URL, provided that `'/path/to/certificate'` is the path to a local file that contains your HTTPS certificate:

```php
$certificateLoader = new \Ocsp\CertificateLoader();
$certificate = $certificateLoader->fromFile('/path/to/certificate');
$certificateInfo = new \Ocsp\CertificateInfo();
$urlOfIssuerCertificate = $certificateInfo->extractIssuerCertificateUrl($certificate);
```

At this point, `$urlOfIssuerCertificate` will contain the URL where the issuer certificate can be downloaded from (if it's an empty string, that means that the issuer certificate URL is not included in your certificate).

## Obtaining the OCSP Responder URL

To check if a certificate is valid, we need to know an URL, provided by the authority that issued the certificate, that can be called to check if the certificate has been revoked.

This URL may be included in the HTTPS certificate itself.

To get it, you can use the following code (provided that `'/path/to/certificate'` is the path to a local file that contains your HTTPS certificate):

```php
$certificateLoader = new \Ocsp\CertificateLoader();
$certificate = $certificateLoader->fromFile('/path/to/certificate');
$certificateInfo = new \Ocsp\CertificateInfo();
$ocspResponderUrl = $certificateInfo->extractOcspResponderUrl($certificate);
```

## Checking if a certificate has been revoked

Once you have the HTTPS certificate, the issuer certificate, and the OCSP Responder URL, you can check if the HTTPS certificate has been revoked, or if it's still valid.

In order to do so, you have to write some code like this (here we use cURL, but you can use any other transport library):

```php
$certificateLoader = new \Ocsp\CertificateLoader();
$certificateInfo = new \Ocsp\CertificateInfo();
$ocsp = new \Ocsp\Ocsp();

// Load the HTTPS certificate and the issuer certificate
$certificate = $certificateLoader->fromFile('/path/to/certificate');
$issuerCertificate = $certificateLoader->fromFile('/path/to/issuer/certificate');

// Extract the relevant data from the two certificates
$requestInfo = $certificateInfo->extractRequestInfo($certificate, $issuerCertificate);

// Build the raw body to be sent to the OCSP Responder URL
$requestBody = $ocsp->buildOcspRequestBodySingle($requestInfo);

// Actually call the OCSP Responder URL (here we use cURL, you can use any library you prefer)
$hCurl = curl_init();
curl_setopt($hCurl, CURLOPT_URL, $ocspResponderUrl);
curl_setopt($hCurl, CURLOPT_RETURNTRANSFER, true);
curl_setopt($hCurl, CURLOPT_POST, true);
curl_setopt($hCurl, CURLOPT_HTTPHEADER, ['Content-Type: ' . \Ocsp\Ocsp::OCSP_REQUEST_MEDIATYPE]);
curl_setopt($hCurl, CURLOPT_SAFE_UPLOAD, true);
curl_setopt($hCurl, CURLOPT_POSTFIELDS, $requestBody);
$result = curl_exec($hCurl);
$info = curl_getinfo($hCurl);
if ($info['http_code'] !== 200) {
    throw new \RuntimeException("Whoops, here we'd expect a 200 HTTP code");
}
if ($info['content_type'] !== \Ocsp\Ocsp::OCSP_RESPONSE_MEDIATYPE) {
    throw new \RuntimeException("Whoops, the Content-Type header of the response seems wrong!");
}

// Decode the raw response from the OCSP Responder
$response = $ocsp->decodeOcspResponseSingle($result);
```

At this point, `$response` contains an instance of the `Ocsp\Response` class:

- the certificate is not revoked if `$response->isRevoked() === false`
- the certificate is revoked if `$response->isRevoked() === true` (you can get the devocation date/time by calling `$response->getRevokedOn()`)
- in case of unknown state, `$response->isRevoked()` will return `null`

## Exceptions

Problems may arise while loading the certificates, creating the request body for the OCSP Responder, analyzing the response from the OCSP Responder.
To catch these errors, you can enclose your code within try/catch statements:

```php
try {
    // code
} catch (\Ocsp\Exception\Exception $problem) {
    // handle the error cases
}
```
