<?php

namespace Devexar\JWTAuth\Tests\Helpers\ServiceProvider;

use Devexar\JWTAuth\Tests\Helpers\UserProviders\UserProvider;
use Illuminate\Foundation\Support\Providers\AuthServiceProvider;
use Illuminate\Support\Facades\Auth;

class TestUserProvider extends AuthServiceProvider
{
    /**
     * Register any application authentication / authorization services.
     *
     * @return void
     */
    public function boot()
    {
        $this->registerPolicies();

        Auth::provider(
            'TestUserProvider',
            function ($app, array $config) {
                return new UserProvider();
            }
        );
    }
}
