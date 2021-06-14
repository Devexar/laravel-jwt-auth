<?php

namespace Devexar\JWTAuth\Providers;

use Devexar\JWTAuth\JWTAuthGuard;
use Devexar\JWTAuth\JWTManager;
use Devexar\JWTAuth\Middlewares\Authenticate;
use Illuminate\Foundation\Support\Providers\AuthServiceProvider;
use Illuminate\Support\Facades\Auth;

class LaravelServiceProvider extends AuthServiceProvider
{
    protected array $middlewareAliases = [
        'jwt.auth' => Authenticate::class,
    ];

    /**
     * Register any application authentication / authorization services.
     *
     * @return void
     */
    public function boot()
    {
        $this->registerPolicies();
        $this->publishes(
            [
                __DIR__ . '/../Config/main.php' => config_path('jwt-auth.php'),
            ],
            'config'
        );
        $this->mergeConfigFrom(__DIR__ . '/../Config/main.php', 'jwt-auth');

        $this->registerMiddlewares();

        Auth::extend(
            'jwt',
            function ($app, $name, array $config) {
                $userProviderId = $config['provider'];
                $userConfig = $app['config']->get('jwt-auth');

                return new JWTAuthGuard(
                    $name,
                    $userConfig['guard'],
                    Auth::createUserProvider($userProviderId),
                    $this->app->make(
                        JWTManager::class,
                        ['config' => $userConfig['jwt']]
                    ),
                    $this->app->get('request')
                );
            }
        );
    }

    protected function registerMiddlewares()
    {
        $router = $this->app['router'];

        $method = method_exists($router, 'aliasMiddleware') ? 'aliasMiddleware' : 'middleware';

        foreach ($this->middlewareAliases as $alias => $middleware) {
            $router->$method($alias, $middleware);
        }
    }
}
