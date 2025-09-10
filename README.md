Validate server to server messaging through Hmac signatures in a laravel project

## Installation
First install the package
```shell
composer require lelectrolux/hmac-utils
```

Then, publish the config file, and **fill the necessary `.env` values**
```shell
php artisan vendor:publish --provider=Lelectrolux\Hmac\Laravel\ServiceProvider
```

## Use-cases

Most of the logic is abstracted for 2 use-cases

### My server recieves a Hmac signed request

Use the Laravel middleware on your corresponding route
```php
use Lelectrolux\Hmac\Laravel\Middleware;

// Any key => secret pair allowed
Route::get('/some/uri')->middleware(Middleware::class)

// Ony those keyed by foo or bar
Route::get('/some/uri')->middleware(Middleware::class.':foo,bar')
```

The hmac uuid will be made available in the [laravel context](https://laravel.com/docs/master/context) at the key `'hmac_request_uuid'` [🔗](https://github.com/Lelectrolux/hmac-utils/blob/930903503e9c2f8f16423d123c9f5b330c8bfc79/src/Laravel/Middleware.php#L41C30-L41C47).

### My server sends a Hmac signed through guzzle

Use the Guzzle middleware factory in your Http client call chain
```php
use Illuminate\Support\Facades\Http;
use Lelectrolux\Hmac\Guzzle\MiddlewareFactory;

Http::createPendingRequest()->withMiddleware($middlewareFactory->make('foo'))->...
```
