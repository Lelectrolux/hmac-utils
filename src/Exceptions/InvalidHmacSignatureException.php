<?php

declare(strict_types=1);

namespace Lelectrolux\Hmac\Exceptions;

use Exception;

class InvalidHmacSignatureException extends Exception
{
    public static function malformedHeader(): self
    {
        return new self('Authorization header is malformed');
    }

    public static function signatureDoesntMatch(): self
    {
        return new self('Authorization header signature does\'t match');
    }

    public static function keyNotAllowed(): self
    {
        return new self('This key is not allowed');
    }

    public static function responseDoesntMatch(): self
    {
        return new self('Response does\'t match request, key or uuid changed');
    }
}
