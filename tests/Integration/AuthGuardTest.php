<?php

namespace Devexar\JWTAuth\Tests\Integration;

use Devexar\JWTAuth\Tests\Helpers\User;
use Devexar\JWTAuth\Tests\JWTAuthTestCase;
use Faker\Provider\Uuid;
use Illuminate\Support\Facades\Auth;

class AuthGuardTest extends JWTAuthTestCase
{
    public function testConfigFileIsLoaded()
    {
        $config = $this->app['config']['jwt-auth'];

        self::assertNotNull($config, 'Missing configuration.');
    }

    public function testUserIsNullIfNotAuthenticated()
    {
        $user = Auth::user();
        self::assertNull($user);
    }

    public function testUserIsSet()
    {
        $user = new User(Uuid::uuid());
        Auth::setUser($user);

        $this->assertNotNull(Auth::user());
        $this->assertSame($user, Auth::user());
    }

    public function testUserIsNotGuestIfAuthenticated()
    {
        $user = new User(Uuid::uuid());
        Auth::setUser($user);

        $this->assertFalse(Auth::guest());
    }

    public function testUserIsGuestIfNotAuthenticated()
    {
        $this->assertTrue(Auth::guest());
    }

    public function testUserIsNotAuthenticatedIfNotSet()
    {
        self::assertFalse(Auth::check());
    }

    public function testUserIsAuthenticatedIfSet()
    {
        $user = new User(Uuid::uuid());
        Auth::setUser($user);

        $this->assertTrue(Auth::check());
        $this->assertSame($user, Auth::user());
    }

    public function testAuthenticatableIdIsReturned()
    {
        $userId = Uuid::uuid();
        $user = new User($userId);
        Auth::setUser($user);

        $this->assertSame($userId, Auth::id());
    }

    public function testAuthenticatableIdReturnsNullIfNoUserSet()
    {
        $this->assertNull(Auth::id());
    }

    public function testUserIsAuthenticatedWhenUserProviderFindsCredentialsMatch()
    {
        $result = $this->app['auth']->validate(['username' => 'Pepe']);
        self::assertNotNull($result);
    }

    public function testUserIsNotAuthenticatedWhenUserProviderDoesntFindMatchingCredentials()
    {
        $result = $this->app['auth']->validate(['username' => 'NotFoundPepe']);
        self::assertNull($result);
    }
}
