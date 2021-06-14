<?php

namespace Devexar\JWTAuth\Tests\Unit;

use Devexar\JWTAuth\Exceptions\InvalidKeyException;
use Devexar\JWTAuth\JWTManager;
use Devexar\JWTAuth\Tests\Helpers\Constants;
use Devexar\JWTAuth\Tests\Helpers\User;
use Illuminate\Contracts\Filesystem\FileNotFoundException;
use PHPUnit\Framework\TestCase;

class JWTManagerTest extends TestCase
{
    protected array $config;

    public function __construct(?string $name = null, array $data = [], $dataName = '')
    {
        parent::__construct($name, $data, $dataName);
        $this->config = include(__DIR__ . '/../../src/Config/main.php');
    }

    /**
     * @throws FileNotFoundException
     * @throws InvalidKeyException
     */
    public function testPayloadIsEncodedSuccessfully()
    {
        $this->config['jwt']['secret'] = Constants::$TEST_CONFIG_SECRET;
        $this->config['jwt']['algorithm'] = 'HS256';

        $jwtManager = new JWTManager($this->config['jwt']);
        $result = $jwtManager->encode($payload = ['prv' => 'users', 'sub' => 'pepe'], false);

        $this->assertSame(
        // phpcs:ignore
            $token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJwcnYiOiJ1c2VycyIsInN1YiI6InBlcGUifQ.yzffno0rTPzw5UZovAP0JM2JA7_pWxB4gzU9ZZXATa0',
            $result
        );
        $this->assertSame($payload, $jwtManager->decode($token));
    }

    /**
     * @throws FileNotFoundException
     * @throws InvalidKeyException
     */
    public function testPayloadIsEncodedSuccessfullyWithKey()
    {
        $this->config['jwt']['keys']['private'] = __DIR__ . '/../Helpers/Keys/testKey';
        $this->config['jwt']['keys']['public'] = __DIR__ . '/../Helpers/Keys/testKey.pem.pub';
        $this->config['jwt']['algorithm'] = 'RS256';

        $jwtManager = new JWTManager($this->config['jwt']);
        $result = $jwtManager->encode($payload = ['grd' => 'users', 'sub' => 'Pepe'], false);

        $this->assertSame(
        // phpcs:ignore
            $token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJncmQiOiJ1c2VycyIsInN1YiI6IlBlcGUifQ.DqDa-K0SqDdwPrk8YaLJAvxVXFr5GbjEDtlkyX7KxP9Yk-rYiD2j9AUbNrQzb30uLdGejCvqejiNOedk55lRRaMTW3fC4vii1rWmV5tpCER3XEgJJ0AXTYKTLMv8Bh2b_Z3doGvGpzLQnEVv2zouZCywLJbMXQoKX2uYtBoNPmc0MMAQn7x9WyD4eXflkeekPkNTvilBr9j_GR8mdH9TYvOAx3RrAQk7QlOSuKTTEU-uNIndovc8HHgeV9yTZRQTIjDMAnsBxPJ5p2zUJ_nA4O2bFWD48-J47WkfiixkezbpF4H3QZA18MsML5KHODJ3Z9NegoLIM8OVGXs8IegABQ',
            $result
        );
        $this->assertSame($payload, $jwtManager->decode($token));
    }

    /**
     * @throws FileNotFoundException
     * @throws InvalidKeyException
     */
    public function testEncodeThrowsExceptionIfKeyOrSecretIsNotProvided()
    {
        $jwtManager = new JWTManager($this->config['jwt']);

        $this->expectException(InvalidKeyException::class);
        $jwtManager->encode(['prv' => 'users', 'sub' => 'pepe']);
    }

    /**
     * @throws FileNotFoundException
     * @throws InvalidKeyException
     */
    public function testEncodeThrowsExceptionIfKeyPathIsInvalid()
    {
        $this->config['jwt']['keys']['private'] = '/var/pepe';

        $jwtManager = new JWTManager($this->config['jwt']);

        $this->expectException(FileNotFoundException::class);
        $jwtManager->encode(['prv' => 'users', 'sub' => 'pepe']);
    }

    /**
     * @throws FileNotFoundException
     * @throws InvalidKeyException
     */
    public function testTokenIsDecodedSuccessfully()
    {
        $this->config['jwt']['secret'] = Constants::$TEST_CONFIG_SECRET;

        // Required claims as null
        $payload = [
            'prv' => 'users',
            'sub' => 'Pepe'
        ];
        $jwtManager = new JWTManager($this->config['jwt']);
        $token = $jwtManager->encode($payload, false);
        $result = $jwtManager->decode($token);

        $this->assertSame($payload, $result);
    }

    /**
     * @throws FileNotFoundException
     * @throws InvalidKeyException
     */
    public function testRequiredClaimsAreAddedToPayload()
    {
        $this->config['jwt']['secret'] = Constants::$TEST_CONFIG_SECRET;

        // Required claims as null
        $payload = [
            'iss' => null,
            'iat' => null,
            'exp' => null,
            'nbf' => null,
            'grd' => null,
            'sub' => 'Pepe'
        ];
        $jwtManager = new JWTManager($this->config['jwt']);
        $token = $jwtManager->encode($payload);
        $result = $jwtManager->decode($token);

        $this->assertSame($payload, $result);
    }

    /**
     * @throws FileNotFoundException
     * @throws InvalidKeyException
     */
    public function testCustomClaimsCanBeAdded()
    {
        $this->config['jwt']['secret'] = Constants::$TEST_CONFIG_SECRET;
        $user = new User('Pepe');
        $customClaims = ['Name' => 'Le Pew', 'Type' => 'Cartoon'];

        $jwtManager = new JWTManager($this->config['jwt']);
        $jwtManager->setGuardId('users');

        $token = $jwtManager->fromUser($user, $customClaims, false);

        $result = $jwtManager->decode($token);

        $this->assertEquals(['grd' => 'users', 'sub' => 'Pepe', 'Name' => 'Le Pew', 'Type' => 'Cartoon'], $result);
    }

    public function testConfigCanBeOverriddenForAudience()
    {
        $this->config['jwt']['aud_config_override'] = [
            'mobile' => [
                'keys' => [
                    'public' => 'path1',
                    'private' => 'path2'
                ],
                'ttl' => [
                    'on_create' => 50,
                    'on_refresh' => 40,
                ],
                'algorithm' => 'RS256',
                'add_guard_claim' => false,
                'required_claims' => ['grd'],
                'leeway' => 30,
                'blacklist_enabled' => false,
                'blacklist_grace_period' => 20
            ]
        ];
        $this->config['jwt']['secret'] = Constants::$TEST_CONFIG_SECRET;

        $jwtManager = new JWTManager($this->config['jwt']);

        $expected = [
            'aud_config_override' => $this->config['jwt']['aud_config_override'],
            'secret' => null,
            'keys' => [
                'public' => 'path1',
                'private' => 'path2'
            ],
            'ttl' => [
                'on_create' => 50,
                'on_refresh' => 40,
            ],
            'algorithm' => 'RS256',
            'add_guard_claim' => false,
            'required_claims' => ['grd'],
            'leeway' => 30,
            'blacklist_enabled' => false,
            'blacklist_grace_period' => 20
        ];

        $configForAudience = $jwtManager->getConfigForAudience('mobile');

        $this->assertSame($expected, $configForAudience);
    }

    public function testOverriddenPrivateKeyIsUsed()
    {
        $this->config['jwt']['aud_config_override'] = [
            'mobile' => [
                'keys' => [
                    'private' => __DIR__ . '/../Helpers/Keys/testKey2',
                    'public' => __DIR__ . '/../Helpers/Keys/testKey2.pem.pub',
                ],
                'algorithm' => 'RS256'
            ]
        ];
        $this->config['jwt']['secret'] = Constants::$TEST_CONFIG_SECRET;

        $payload = [
            'iss' => null,
            'iat' => null,
            'exp' => null,
            'nbf' => null,
            'grd' => 'users',
            'sub' => 'Pepe',
            'aud' => 'mobile'
        ];
        $jwtManager = new JWTManager($this->config['jwt']);
        // phpcs:ignore
        $expectedToken = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOm51bGwsImlhdCI6bnVsbCwiZXhwIjpudWxsLCJuYmYiOm51bGwsImdyZCI6InVzZXJzIiwic3ViIjoiUGVwZSIsImF1ZCI6Im1vYmlsZSJ9.VAaWhrd-j8XKR4Mfehcx0-7EnK0DIJJnoX_emsvltkUukOcqTKy5PDICSFJgLT6eLhhs4n0lZW9AMvXFY5s-vN2xIq8o4f_kFkKy45vDKozZXhDLs0edgfE3nIXdAMTkPiRrnz90yHGkfDkwOw2VbtO8veFTtaU44suVOq9mWkSJfVi0BaFfqTzNmDCpdo2eGBN2YFhjzTkvmlRhMlTqPo0R7SCjacRMv6UXlmdlgR8EDxV1YHQZ0zlpUKvEQLzUZeXXLPMxc-dELmM5it7iOc92m9uak01h7f95yp4RBuWYivfEtctfLBLR1DPpaNlr9Iw_gWqhObMspsfq-wvhfA';

        $this->assertSame($expectedToken, $jwtManager->encode($payload));
    }

    public function testOverriddenKeyForAudienceDecodesCorrectly()
    {
        $this->config['jwt']['aud_config_override'] = [
            'mobile' => [
                'keys' => [
                    'private' => __DIR__ . '/../Helpers/Keys/testKey2',
                    'public' => __DIR__ . '/../Helpers/Keys/testKey2.pem.pub',
                ],
                'algorithm' => 'RS256'
            ]
        ];
        $this->config['jwt']['secret'] = Constants::$TEST_CONFIG_SECRET;

        $payload = [
            'iss' => null,
            'iat' => null,
            'exp' => null,
            'nbf' => null,
            'grd' => 'users',
            'sub' => 'Pepe',
            'aud' => 'mobile'
        ];
        $jwtManager = new JWTManager($this->config['jwt']);
        $token = $jwtManager->encode($payload);

        $decodedPayload = $jwtManager->decode($token);
        $this->assertSame($payload, $decodedPayload);
    }
}
