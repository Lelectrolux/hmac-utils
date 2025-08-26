<?php

declare(strict_types=1);

namespace Lelectrolux\Hmac\Guzzle;

use Lelectrolux\Hmac\Exceptions\InvalidHmacSignatureException;
use Lelectrolux\Hmac\Hmac;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Ramsey\Uuid\Uuid;

final class MiddlewareFactory
{
    public function __construct(
        private Hmac $hmac,
    ) {}

    public function make(string $key): callable
    {
        return function (callable $handler) use ($key): callable {
            return function (RequestInterface $request, array $options) use ($handler, $key) {
                $uuid = Uuid::uuid7();
                $request = $request->withHeader('Authorization', $this->hmac->generateHeaderValue($key, (string) $request->getBody(), $uuid));

                return $handler($request, $options)->then(function (ResponseInterface $response) use ($key, $uuid) {
                    [$keySegment, $signSegment, $uuidSegment] = $this->hmac->extractFromHeaderValue($response->getHeaderLine('Authorization'));

                    if ($key !== $keySegment || ! $uuid->equals($uuidSegment)) {
                        throw InvalidHmacSignatureException::responseDoesntMatch();
                    }

                    $this->hmac->validateParts($signSegment, $keySegment, $uuidSegment, (string) $response->getBody());

                    return $response;
                });
            };
        };
    }
}
