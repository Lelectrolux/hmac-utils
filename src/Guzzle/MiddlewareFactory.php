<?php

declare(strict_types=1);

namespace Lelectrolux\Hmac\Guzzle;

use Lelectrolux\Hmac\Exceptions\InvalidHmacSignatureException;
use Lelectrolux\Hmac\Hmac;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Ramsey\Uuid\Uuid;

final readonly class MiddlewareFactory
{
    public function __construct(
        private Hmac $hmac,
    ) {}

    public function make(string $key): callable
    {
        return function (callable $handler) use ($key): callable {
            return function (RequestInterface $request, array $options) use ($handler, $key) {
                $queryString = $request->getUri()->getQuery();
                $uuid = Uuid::uuid7();

                $authorization = $this->hmac->generateHeaderValue($key, $queryString, (string) $request->getBody(), $uuid);

                $request = $request->withHeader('Authorization', $authorization);

                return $handler($request, $options)->then(function (ResponseInterface $response) use ($key, $queryString, $uuid) {
                    [$keySegment, $signSegment, $uuidSegment] = $this->hmac->extractFromHeaderValue($response->getHeaderLine('Authorization'));

                    if ($key !== $keySegment || ! $uuid->equals($uuidSegment)) {
                        throw InvalidHmacSignatureException::responseDoesntMatch();
                    }

                    $this->hmac->validateParts($signSegment, $keySegment, $uuidSegment, $queryString, (string) $response->getBody());

                    return $response;
                });
            };
        };
    }
}
