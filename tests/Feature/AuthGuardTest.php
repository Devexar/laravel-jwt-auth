<?php

namespace Devexar\JWTAuth\Tests\Feature;

use Devexar\JWTAuth\Exceptions\InvalidKeyException;
use Devexar\JWTAuth\JWTManager;
use Devexar\JWTAuth\Tests\Helpers\Constants;
use Devexar\JWTAuth\Tests\JWTAuthTestCase;
use Illuminate\Contracts\Filesystem\FileNotFoundException;

class AuthGuardTest extends JWTAuthTestCase
{
    protected array $config;

    public function __construct(?string $name = null, array $data = [], $dataName = '')
    {
        parent::__construct($name, $data, $dataName);
        $this->config = include(__DIR__ . '/../../src/Config/main.php');
        $this->config['jwt']['secret'] = Constants::$TEST_CONFIG_SECRET;
        $this->config['jwt']['algorithm'] = Constants::$TEST_CONFIG_ALGORITHM;
    }

    /**
     * @dataProvider validTokenProvider
     * @param string $jwt
     */
    public function testAccessingProtectedUrlIsAllowedForValidToken(string $jwt)
    {
        $result = $this->json('GET', '/protected', [], ['Authorization' => $jwt]);
        $this->assertSame(200, $result->getStatusCode());
    }

    /**
     * @dataProvider invalidTokenProvider
     * @param string $jwt
     */
    public function testAccessingProtectedUrlIsForbiddenForInvalidToken(string $jwt)
    {
        $result = $this->json('GET', '/protected', [], ['Authorization' => $jwt]);
        $this->assertSame(401, $result->getStatusCode());
    }

    /**
     * @return array[]
     * @throws FileNotFoundException
     * @throws InvalidKeyException
     */
    public function validTokenProvider(): array
    {
        $jwtManager = new JWTManager($this->config['jwt']);

        return [
            'Valid User Subject' => [
                $jwtManager->encode(
                    [
                        'sub' => 'Pepe',
                        'iss' => 'Laravel JWT Auth',
                        'iat' => time(),
                        'exp' => time() + 60,
                        'nbf' => time(),
                        'grd' => 'jwt_users',
                    ]
                )
            ],
            'Valid Admin Subject' => [
                $jwtManager->encode(
                    [
                        'sub' => 'PepeAdmin',
                        'iss' => 'Laravel JWT Auth',
                        'iat' => time(),
                        'exp' => time() + 60,
                        'nbf' => time(),
                        'grd' => 'jwt_admins',
                    ]
                )
            ],
        ];
    }

    /**
     * @return array[]
     * @throws FileNotFoundException
     * @throws InvalidKeyException
     */
    public function invalidTokenProvider(): array
    {
        $jwtManager = new JWTManager($this->config['jwt']);

        return [
            'Valid User Missing Required Claim iss' => [
                $jwtManager->encode(
                    [
                        'sub' => 'Pepe',
                        'iat' => time(),
                        'exp' => time() + 60,
                        'nbf' => time(),
                        'grd' => 'jwt_users',
                    ]
                )
            ],
            'Valid User Missing Required Claim iat' => [
                $jwtManager->encode(
                    [
                        'sub' => 'Pepe',
                        'iss' => 'Laravel JWT Auth',
                        'exp' => time() + 60,
                        'nbf' => time(),
                        'grd' => 'jwt_users',
                    ]
                )
            ],
            'Valid User Missing Required Claim exp' => [
                $jwtManager->encode(
                    [
                        'sub' => 'Pepe',
                        'iss' => 'Laravel JWT Auth',
                        'iat' => time(),
                        'nbf' => time(),
                        'grd' => 'jwt_users',
                    ]
                )
            ],
            'Valid User Missing Required Claim nbf' => [
                $jwtManager->encode(
                    [
                        'sub' => 'Pepe',
                        'iss' => 'Laravel JWT Auth',
                        'iat' => time(),
                        'exp' => time() + 60,
                        'grd' => 'jwt_users',
                    ]
                )
            ],
            'Valid User Missing Required Claim grd' => [
                $jwtManager->encode(
                    [
                        'sub' => 'Pepe',
                        'iss' => 'Laravel JWT Auth',
                        'iat' => time(),
                        'exp' => time() + 60,
                        'nbf' => time(),
                    ]
                )
            ],
            'Invalid User' => [
                $jwtManager->encode(
                    [
                        'sub' => 'InvalidPepe',
                        'iss' => 'Laravel JWT Auth',
                        'iat' => time(),
                        'exp' => time() + 60,
                        'nbf' => time(),
                        'grd' => 'jwt_users',
                    ]
                )
            ],
            'Valid User but different Guard #1' => [
                $jwtManager->encode(
                    [
                        'sub' => 'Pepe',
                        'iss' => 'Laravel JWT Auth',
                        'iat' => time(),
                        'exp' => time() + 60,
                        'nbf' => time(),
                        'grd' => 'jwt_admins',
                    ]
                )
            ],
            'Valid User but different Guard #2' => [
                $jwtManager->encode(
                    [
                        'sub' => 'PepeAdmin',
                        'iss' => 'Laravel JWT Auth',
                        'iat' => time(),
                        'exp' => time() + 60,
                        'nbf' => time(),
                        'grd' => 'jwt_users',
                    ]
                )
            ],
        ];
    }

    public function testDecodeIsCalledOnlyOnceForDifferentGuardsWithSameToken()
    {
        $spy = $this->spy(JWTManager::class);
        $this->app->bind(
            JWTManager::class,
            function () use ($spy) {
                return $spy;
            }
        );

        $jwtManager = new JWTManager($this->config['jwt']);
        $jwt = $jwtManager->encode(
            [
                'sub' => 'PepeAdmin',
                'iss' => 'Laravel JWT Auth',
                'iat' => time(),
                'exp' => time() + 60,
                'nbf' => time(),
                'grd' => 'jwt_admins',
            ]
        );

        $this->json('GET', '/protected', [], ['Authorization' => $jwt]);
        $spy->shouldHaveReceived('decode')->once();
    }
}
