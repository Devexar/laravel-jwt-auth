<?php

namespace Devexar\JWTAuth;

use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;

class JWTAuthGuard implements Guard
{
    use GuardHelpers;

    /**
     * @var Request
     */
    protected Request $request;

    /**
     * @var JWTManager
     */
    protected JWTManager $JWTManager;

    /**
     * @var array
     */
    protected array $config;

    /**
     * @var string
     */
    protected string $id;

    /**
     * @var array Used to avoid decoding in each Guard if multiple are declared.
     */
    protected static array $lastPayload = [];

    /**
     * @var string Used to avoid decoding in each Guard if multiple are declared.
     */
    protected static string $lastToken = '';

    /**
     * Create a new authentication guard.
     *
     * @param string $id
     * @param array $config
     * @param UserProvider $provider
     * @param JWTManager $JWTManager
     * @param Request $request
     */
    public function __construct(
        string $id,
        array $config,
        UserProvider $provider,
        JWTManager $JWTManager,
        Request $request
    ) {
        $this->id = $id;
        $this->provider = $provider;
        $this->JWTManager = $JWTManager;
        $this->JWTManager->setGuardId($id);
        $this->request = $request;
        $this->config = $config;
    }

    /**
     * @return Authenticatable|null
     */
    public function user()
    {
        if ($this->user !== null) {
            return $this->user;
        }

        if ($token = (string)$this->request->header('Authorization')) {
            try {
                if (self::$lastToken === $token) {
                    $payload = self::$lastPayload;
                } else {
                    $payload = $this->JWTManager->decode($token);
                    $this->JWTManager->validatePayload($payload);
                    self::$lastToken = $token;
                    self::$lastPayload = $payload;
                }

                if ($payload['grd'] === $this->id) {
                    return $this->user = $this->provider->retrieveById($payload['sub']);
                }
            } catch (\Exception $e) {
            }
        }

        return null;
    }

    public function validate(array $credentials = [])
    {
        return $this->user = $this->provider->retrieveByCredentials($credentials);
    }

    /**
     * @return JWTManager
     */
    public function jwt(): JWTManager
    {
        return $this->JWTManager;
    }
}
