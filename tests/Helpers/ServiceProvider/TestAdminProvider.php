<?php

namespace Devexar\JWTAuth\Tests\Helpers\ServiceProvider;

use Devexar\JWTAuth\Tests\Helpers\UserProviders\AdminProvider;
use Illuminate\Foundation\Support\Providers\AuthServiceProvider;
use Illuminate\Support\Facades\Auth;

class TestAdminProvider extends AuthServiceProvider
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
            'TestAdminProvider',
            function ($app, array $config) {
                return new AdminProvider();
            }
        );
    }
}
