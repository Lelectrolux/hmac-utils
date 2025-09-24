<?php

declare(strict_types=1);

namespace Lelectrolux\Hmac;

use Lelectrolux\Hmac\Exceptions\InvalidHmacSignatureException;
use Ramsey\Uuid\Uuid;
use Ramsey\Uuid\UuidInterface;
use SensitiveParameter;

final readonly class Hmac
{
    public function __construct(
        #[SensitiveParameter]
        private array $config,
    ) {}

    public function extractFromHeaderValue(string $header): array
    {
        $segments = explode(':', $header, 3);
        $keySegment = $segments[0] ?? null;
        $signSegment = $segments[1] ?? null;
        $uuidSegment = $segments[2] ?? null;

        if ($signSegment === null || $keySegment === null || ! Uuid::isValid($uuidSegment)) {
            throw InvalidHmacSignatureException::malformedHeader();
        }

        $uuid = Uuid::fromString($uuidSegment);

        if ($uuid->getFields()->getVersion() !== 7) {
            throw InvalidHmacSignatureException::malformedHeader();
        }

        return [$keySegment, $signSegment, $uuid];
    }

    public function validateParts(
        string $sign,
        string $key,
        UuidInterface $uuid,
        string $queryString,
        string $body,
    ): void {
        if (! hash_equals($this->generateHmac($key, $queryString, $body, $uuid), $sign)) {
            throw InvalidHmacSignatureException::signatureDoesntMatch();
        }
    }

    public function generateHmac(
        string $key,
        string $queryString,
        string $body,
        UuidInterface $uuid,
    ): string {
        return hash_hmac('sha3-256', $key.$queryString.$body.$uuid, $this->config[$key]);
    }

    public function generateHeaderValue(
        string $key,
        string $queryString,
        string $body,
        UuidInterface $uuid,
    ): string {
        return "{$key}:{$this->generateHmac($key, $queryString, $body, $uuid)}:{$uuid}";
    }
}
