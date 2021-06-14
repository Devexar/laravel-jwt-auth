<?php

namespace Devexar\JWTAuth\Tests\Helpers\UserProviders;

use Devexar\JWTAuth\Tests\Helpers\User;
use Illuminate\Contracts\Auth\Authenticatable;

class UserProvider implements \Illuminate\Contracts\Auth\UserProvider
{

    /**
     * @var Authenticatable
     */
    protected Authenticatable $user;

    public function __construct()
    {
        $this->user = new User('Pepe');
    }

    /**
     * @inheritDoc
     */
    public function retrieveById($identifier)
    {
        if ($identifier === 'Pepe') {
            return $this->user;
        }

        return null;
    }

    /**
     * @inheritDoc
     */
    public function retrieveByToken($identifier, $token): ?Authenticatable
    {
        // Won't implement, as this is for Remember Me login form functionality.
    }

    /**
     * @inheritDoc
     */
    public function updateRememberToken(Authenticatable $user, $token)
    {
        // Won't implement, as this is for Remember Me login form functionality.
    }

    /**
     * @inheritDoc
     */
    public function retrieveByCredentials(array $credentials)
    {
        if (isset($credentials['username']) && $credentials['username'] === 'Pepe') {
            return $this->user;
        }

        return null;
    }

    /**
     * @inheritDoc
     */
    public function validateCredentials(Authenticatable $user, array $credentials)
    {
        // TODO: Implement validateCredentials() method.
    }
}
