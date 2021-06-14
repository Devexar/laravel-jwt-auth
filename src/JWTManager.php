<?php

namespace Devexar\JWTAuth;

use Devexar\JWTAuth\Exceptions\InvalidKeyException;
use Devexar\JWTAuth\Exceptions\MissingRequiredClaimException;
use Dotenv\Exception\InvalidFileException;
use Firebase\JWT\JWT;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Filesystem\FileNotFoundException;
use Illuminate\Http\Request;

class JWTManager
{

    /**
     * @var array
     */
    protected array $config;

    /**
     * @var string|null
     */
    protected ?string $token;

    /**
     * @var string|null
     */
    protected ?string $guardId = null;

    /**
     * @var string|null Used to sign the token.
     */
    protected ?string $encodingKey = null;

    /**
     * @var string|null Used to verify the signature of the token.
     */
    protected ?string $decodingKey = null;

    protected Request $request;

    /**
     * JWTHelper constructor.
     * @param array $config
     */
    public function __construct(array $config)
    {
        $this->config = $config;
    }

    /**
     * General method to encode a payload.
     * You can put whatever you want here.
     * To encode objects implementing Authenticatable, use fromUser()
     * @param $payload
     * @param $addMissingRequiredClaims
     * @return string
     * @throws FileNotFoundException
     * @throws InvalidKeyException
     */
    public function encode(array $payload, bool $addMissingRequiredClaims = true): string
    {
        $overriddenConfig = $this->getConfig();
        JWT::$leeway = $overriddenConfig['leeway'];
        
        // The following is necessary to comply with Audience config override, in case that the given audience
        // has a different decoding key.
        try {
            if (isset($payload['aud'])) {
                $overriddenConfig = $this->getConfigForAudience($payload['aud']);
            }
        } catch (\Exception $e) {
            // Fail silently. If any error, it will be caught and thrown by JWT library.
        }

        $shouldReloadKey = $this->config['secret'] !== $overriddenConfig['secret']
            || $this->config['keys']['private'] !== $overriddenConfig['keys']['private'];

        if (!$this->encodingKey || $shouldReloadKey) {
            $this->encodingKey = $this->loadEncodingKey($overriddenConfig);
        }

        if ($addMissingRequiredClaims) {
            $payload = $payload + $this->getRequiredClaimsDefaults();
        }

        return JWT::encode($payload, $this->encodingKey, $overriddenConfig['algorithm']);
    }

    /**
     * @param $token
     * @return array
     * @throws InvalidFileException|InvalidKeyException|FileNotFoundException
     */
    public function decode($token): array
    {
        $overriddenConfig = $this->getConfig();
        JWT::$leeway = $overriddenConfig['leeway'];

        // The following is necessary to comply with Audience config override, in case that the given audience
        // has a different decoding key.
        try {
            $b64payload = explode('.', $token)[1];
            $payload = (array)JWT::jsonDecode(JWT::urlsafeB64Decode($b64payload));
            if (isset($payload['aud'])) {
                $overriddenConfig = $this->getConfigForAudience($payload['aud']);
            }
        } catch (\Exception $e) {
            // Fail silently. If any error, it will be caught and thrown by JWT library.
        }

        $shouldReloadKey = $this->config['secret'] !== $overriddenConfig['secret']
            || $this->config['keys']['private'] !== $overriddenConfig['keys']['private'];

        if (!$this->decodingKey || $shouldReloadKey) {
            $this->decodingKey = $this->loadDecodingKey($overriddenConfig);
        }

        return (array)JWT::decode($token, $this->decodingKey, [$overriddenConfig['algorithm']]);
    }

    /**
     * @TODO: Make a way to let users define a class/function that will return the required claims default values.
     * @return array
     */
    public function getRequiredClaimsDefaults(): array
    {
        $claims = [];
        foreach ($this->config['required_claims'] as $claimId) {
            $claims[$claimId] = null;
        }

        return $claims;
    }

    /**
     * @param $payload
     * @param $verifyRequiredClaims
     * @throws MissingRequiredClaimException
     */
    public function validatePayload($payload, $verifyRequiredClaims = true)
    {
        if ($verifyRequiredClaims) {
            foreach ($this->getConfig()['required_claims'] as $claim) {
                if (!isset($payload[$claim])) {
                    throw new MissingRequiredClaimException("Required claim '$claim' is missing in the payload.");
                }
            }
        }
    }

    /**
     * @param Authenticatable $user
     * @param array $customClaims
     * @param bool $addMissingRequiredClaims
     * @return string
     * @throws FileNotFoundException
     * @throws InvalidKeyException
     */
    public function fromUser(
        Authenticatable $user,
        array $customClaims = [],
        bool $addMissingRequiredClaims = true
    ): string {
        if (!$this->guardId) {
            throw new \RuntimeException('Provider ID is required to be set.');
        }

        return $this->encode(
            array_merge(
                [
                    'sub' => $user->getAuthIdentifier(),
                    'grd' => $this->guardId,
                ],
                $customClaims
            ),
            $addMissingRequiredClaims
        );
    }

    public function blacklist($token)
    {
    }

    public function unblacklist($token)
    {
    }

    public function isBlacklisted($token)
    {
    }

    /**
     * Check if a token is valid
     * @param $token
     * @return bool
     */
    public function isValid($token): bool
    {
        try {
            $this->decode($token);

            return true;
        } catch (\Exception $e) {
            return false;
        }
    }


    public function getError()
    {
    }

    public function setProviderName()
    {
    }

    /**
     * @param string $audience
     * @return array
     */
    public function getConfigForAudience(string $audience): array
    {
        if (isset($this->config['aud_config_override'][$audience])) {
            $overriddenConfig = array_replace_recursive($this->config, $this->config['aud_config_override'][$audience]);

            if (isset($this->config['aud_config_override'][$audience]['keys'])) {
                $overriddenConfig['secret'] = null;
            }

            if (isset($this->config['aud_config_override'][$audience]['required_claims'])) {
                // phpcs:ignore
                $overriddenConfig['required_claims'] = $this->config['aud_config_override'][$audience]['required_claims'];
            }

            return $overriddenConfig;
        }

        return $this->config;
    }

    /**
     * @return array
     */
    public function getConfig(): array
    {
        return $this->config;
    }

    /**
     * @param array $config
     */
    public function setConfig(array $config): void
    {
        $this->config = $config;
    }

    /**
     * @return string|null
     */
    public function getToken(): ?string
    {
        return $this->token;
    }

    /**
     * @param string|null $token
     */
    public function setToken(?string $token): void
    {
        $this->token = $token;
    }

    /**
     * @return string|null
     */
    public function getGuardId(): ?string
    {
        return $this->guardId;
    }

    /**
     * @param string|null $providerId
     */
    public function setGuardId(?string $providerId): void
    {
        $this->guardId = $providerId;
    }

    /**
     * @param array $overriddenConfig
     * @return string
     * @throws InvalidKeyException
     * @throws FileNotFoundException
     */
    protected function loadDecodingKey(array $overriddenConfig = []): string
    {
        $config = $overriddenConfig ?: $this->config;

        $keyFilePath = $config['keys']['public'];

        if ($keyFilePath) {
            if (!is_file($keyFilePath)) {
                throw new FileNotFoundException('The public key file path is not valid.');
            }
            $key = file_get_contents($keyFilePath);
            if ($key === false) {
                throw new InvalidFileException('The public key file could not be loaded.');
            }
        } else {
            $key = $config['secret'];
        }

        if (!$key) {
            throw new InvalidKeyException('Decoding Key not configured.');
        }

        return $key;
    }

    /**
     * @param array $overriddenConfig
     * @return string
     * @throws InvalidKeyException
     * @throws FileNotFoundException
     */
    protected function loadEncodingKey(array $overriddenConfig = []): string
    {
        $config = $overriddenConfig ?: $this->config;

        $keyFilePath = $config['keys']['private'];

        if ($keyFilePath) {
            if (!is_file($keyFilePath)) {
                throw new FileNotFoundException('The private key file path is not valid.');
            }
            $key = file_get_contents($keyFilePath);
            if ($key === false) {
                throw new InvalidFileException('The private key file could not be loaded.');
            }
        } else {
            $key = $config['secret'];
        }

        if (!$key) {
            throw new InvalidKeyException('Encoding Key not configured.');
        }

        return $key;
    }
}
