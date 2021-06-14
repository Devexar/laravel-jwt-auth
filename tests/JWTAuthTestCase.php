<?php

namespace Devexar\JWTAuth\Tests;

use Devexar\JWTAuth\Providers\LaravelServiceProvider;
use Devexar\JWTAuth\Tests\Helpers\Constants;
use Illuminate\Foundation\Application;
use Illuminate\Routing\Router;
use Orchestra\Testbench\TestCase;

class JWTAuthTestCase extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [
            'Devexar\JWTAuth\Providers\LaravelServiceProvider',
            'Devexar\JWTAuth\Tests\Helpers\ServiceProvider\TestUserProvider',
            'Devexar\JWTAuth\Tests\Helpers\ServiceProvider\TestAdminProvider'
        ];
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->artisan('vendor:publish', ['--provider' => LaravelServiceProvider::class]);

        /** @var Router $router */
        $router = $this->app['router'];
        $router->get('/protected', 'Devexar\JWTAuth\Tests\Helpers\ApiController@protected')->middleware(
            'jwt.auth:jwt_users,jwt_admins'
        );
        $router->get('/admins/protected', 'Devexar\JWTAuth\Tests\Helpers\ApiController@protected')->middleware(
            'jwt.auth:jwt_admins'
        );
    }

    /**
     * Define environment setup.
     *
     * @param Application $app
     * @return void
     * @noinspection PhpMissingParamTypeInspection
     */
    protected function getEnvironmentSetUp($app)
    {
        $app['config']->set('auth.defaults.guard', 'jwt_users');
        $app['config']->set(
            'auth.guards',
            [
                'jwt_users' => ['driver' => 'jwt', 'provider' => 'users'],
                'jwt_admins' => ['driver' => 'jwt', 'provider' => 'admins']
            ]
        );
        $app['config']->set(
            'auth.providers',
            [
                'users' => ['driver' => 'TestUserProvider'],
                'admins' => ['driver' => 'TestAdminProvider'],
            ],
        );
        $app['config']->set(
            'jwt-auth.jwt.secret',
            Constants::$TEST_CONFIG_SECRET
        );
        $app['config']->set(
            'jwt-auth.guard.show_error_reason',
            true
        );
    }
}
