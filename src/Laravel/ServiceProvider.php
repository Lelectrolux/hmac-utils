<?php

declare(strict_types=1);

namespace Lelectrolux\Hmac\Laravel;

use Lelectrolux\Hmac\Hmac;

class ServiceProvider extends \Illuminate\Support\ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(Hmac::class, fn () => new Hmac(config('hmac', [])));
    }

    public function boot(): void
    {
        $this->publishes([__DIR__.'/../../config/hmac.php' => config_path('hmac.php')]);
    }
}
