<?php

declare(strict_types=1);

namespace Lelectrolux\Hmac\Laravel;

use Closure;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Log\Context\Repository;
use Lelectrolux\Hmac\Exceptions\InvalidHmacSignatureException;
use Lelectrolux\Hmac\Hmac;

final class Middleware
{
    public function __construct(
        private Hmac $hmac,
        private Repository $context,
        private ExceptionHandler $exceptionHandler,
    ) {}

    public function handle(Request $request, Closure $next, string ...$allowedKeys): Response
    {
        try {
            [$key, $sign, $uuid] = $this->hmac->extractFromHeaderValue($request->headers->get('Authorization'));

            if ($allowedKeys !== [] && ! in_array($key, $allowedKeys, true)) {
                throw InvalidHmacSignatureException::keyNotAllowed();
            }

            $this->hmac->validateParts($sign, $key, $uuid, $request->getContent());
        } catch (InvalidHmacSignatureException $exception) {
            $this->exceptionHandler->report($exception);

            abort(401);
        }

        $this->context->add('hmac_request_uuid', $uuid);

        $response = $next($request);

        $response->headers->set('Authorization', $this->hmac->generateHeaderValue($key, $response->getContent(), $uuid));

        return $response;
    }
}
