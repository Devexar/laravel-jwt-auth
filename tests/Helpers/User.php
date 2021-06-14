<?php

namespace Devexar\JWTAuth\Tests\Helpers;

use Illuminate\Contracts\Auth\Authenticatable;

class User implements Authenticatable
{

    /**
     * @var mixed
     */
    protected $id;

    public function __construct($id)
    {
        $this->id = $id;
    }

    /**
     * @inheritDoc
     */
    public function getAuthIdentifierName()
    {
        // TODO: Implement getAuthIdentifierName() method.
    }

    /**
     * @inheritDoc
     */
    public function getAuthIdentifier()
    {
        return $this->id;
    }

    /**
     * @inheritDoc
     */
    public function getAuthPassword()
    {
        // TODO: Implement getAuthPassword() method.
    }

    /**
     * @inheritDoc
     */
    public function getRememberToken()
    {
        // TODO: Implement getRememberToken() method.
    }

    /**
     * @inheritDoc
     */
    public function setRememberToken($value)
    {
        // TODO: Implement setRememberToken() method.
    }

    /**
     * @inheritDoc
     */
    public function getRememberTokenName()
    {
        // TODO: Implement getRememberTokenName() method.
    }
}
