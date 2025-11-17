<?php

namespace App\Tests\Controller;

use App\Entity\User;
use App\Enum\UserRole;
use Doctrine\ORM\EntityManagerInterface;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
class UserControllerTest extends WebTestCase
{
    private $client;
    private EntityManagerInterface $entityManager;
    private UserPasswordHasherInterface $passwordHasher;
    private string $secret;
    private string $algorithm;

    protected function setUp(): void
    {
        parent::setUp();
        $this->client           = static::createClient();
        $container              = static::getContainer();
        $this->entityManager    = $container->get(EntityManagerInterface::class);
        $this->passwordHasher   = $container->get(UserPasswordHasherInterface::class);
        $this->secret           = $container->getParameter('app.token.secret');
        $this->algorithm        = $container->getParameter('app.token.algorithm.default');

        // Clean database before each test
        $this->cleanDatabase();
    }
    
    public function createTestJwt(string $identifier, int $expirationMinutes = 60): string
    {
        $now        = new \DateTimeImmutable();
        $expiration = $now->modify("+$expirationMinutes minutes");
        $jwtPayload = [
            'iat' => $now->getTimestamp(),
            'exp' => $expiration->getTimestamp(),
            'sub' => $identifier,
            'type' => 'session'
        ];
        $token = JWT::encode($jwtPayload, $this->secret, $this->algorithm);
        return $token;
    }
    /**
     * index() testing methods
     */
    public function testIndexWithNoFiltersReturnsArrayOfUsers(): void
    {
        $user = $this->createTestUser(
            'test@email.com',
            'testUsername',
            'correctPass',
            true,
            UserRole::Admin
        );
        $token = $this->createTestJwt($user->getEmail());

        $this->client->request(
            'GET',
            '/api/user',
            [],
            [],
            [
                'HTTP_AUTHORIZATION' => "Bearer $token",
                'CONTENT_TYPE' => 'application/json',
                'HTTP_ACCEPT'  => 'application/json',
            ]
        );

        $this->assertResponseIsSuccessful();
        $responseContent = $this->client->getResponse()->getContent();
        $data = json_decode($responseContent, true);
        $this->assertIsArray($data);
        $this->assertArrayHasKey('data', $data);
        $this->assertArrayHasKey('error', $data);
        $this->assertEmpty($data['error']);
        $this->assertArrayHasKey('users', $data['data']);
        $this->assertNotEmpty($data['data']['users']);
        $this->assertIsArray($data['data']['users']);
    }
    public function testIndexWithFiltersReturnsFilteredUsers(): void
    {
        $user = $this->createTestUser(
            'test@email.com',
            'testUsername',
            'correctPass',
            true,
            UserRole::Admin
        );
        $this->createTestUser(
            'test2@email.com',
            'testUsername2',
            'correctPass',
            false
        );
        $token = $this->createTestJwt($user->getEmail());

        $this->client->request(
            'GET',
            '/api/user?status=active',
            [],
            [],
            [
                'HTTP_AUTHORIZATION' => "Bearer $token",
                'CONTENT_TYPE' => 'application/json',
                'HTTP_ACCEPT'  => 'application/json',
            ]
        );

        $this->assertResponseIsSuccessful();
        $responseContent = $this->client->getResponse()->getContent();
        $data = json_decode($responseContent, true);
        $this->assertIsArray($data);
        $this->assertArrayHasKey('data', $data);
        $this->assertArrayHasKey('error', $data);
        $this->assertEmpty($data['error']);
        $this->assertArrayHasKey('users', $data['data']);
        $this->assertNotEmpty($data['data']['users']);
        $this->assertIsArray($data['data']['users']);
        $this->assertEquals(1, $data['data']['totalCount']);

    }
    /**
     * get() testing methods
     */
    public function testGetWithCorrectIdReturnsUser(): void
    {
        $user = $this->createTestUser(
            'test@email.com',
            'testUsername',
            'correctPass',
            true,
            UserRole::Admin
        );
        $token = $this->createTestJwt($user->getEmail());

        $this->client->request(
            'GET',
            '/api/user/'.$user->getId(),
            [],
            [],
            [
                'HTTP_AUTHORIZATION' => "Bearer $token",
                'CONTENT_TYPE' => 'application/json',
                'HTTP_ACCEPT'  => 'application/json',
            ]
        );

        $this->assertResponseIsSuccessful();
        $responseContent = $this->client->getResponse()->getContent();
        $data = json_decode($responseContent, true);
        $this->assertIsArray($data);
        $this->assertArrayHasKey('data', $data);
        $this->assertArrayHasKey('error', $data);
        $this->assertEmpty($data['error']);
        $this->assertArrayHasKey('user', $data['data']);
        $this->assertNotEmpty($data['data']['user']);
        $this->assertIsArray($data['data']['user']);
        $this->assertEquals($user->toArray(), $data['data']['user']);
    }
    public function testGetWithWrongIdReturnsError(): void
    {
        $user = $this->createTestUser(
            'test@email.com',
            'testUsername',
            'correctPass',
            true,
            UserRole::Admin
        );
        $token = $this->createTestJwt($user->getEmail());

        $this->client->request(
            'GET',
            '/api/user/9999999',
            [],
            [],
            [
                'HTTP_AUTHORIZATION' => "Bearer $token",
                'CONTENT_TYPE' => 'application/json',
                'HTTP_ACCEPT'  => 'application/json',
            ]
        );
        $this->assertResponseStatusCodeSame(404);
        $responseContent = $this->client->getResponse()->getContent();
        $data = json_decode($responseContent, true);
        $this->assertIsArray($data);
        $this->assertArrayHasKey('data', $data);
        $this->assertArrayHasKey('error', $data);
        $this->assertArrayHasKey('message', $data['error']);
        $this->assertEquals('NOT_FOUND', $data['error']['message']);
    }
    public function testGetWithInvalidIdReturnsError(): void
    {
        $user = $this->createTestUser(
            'test@email.com',
            'testUsername',
            'correctPass',
            true,
            UserRole::Admin
        );
        $token = $this->createTestJwt($user->getEmail());

        $this->client->request(
            'GET',
            '/api/user/example',
            [],
            [],
            [
                'HTTP_AUTHORIZATION' => "Bearer $token",
                'CONTENT_TYPE' => 'application/json',
                'HTTP_ACCEPT'  => 'application/json',
            ]
        );

        $this->assertResponseStatusCodeSame(404);
        $responseContent = $this->client->getResponse()->getContent();
        $data = json_decode($responseContent, true);
        $this->assertIsArray($data);
        $this->assertArrayHasKey('data', $data);
        $this->assertArrayHasKey('error', $data);
        $this->assertArrayHasKey('message', $data['error']);
        $this->assertEquals('NOT_FOUND', $data['error']['message']);
    }
    
    /**
     * patch() testing methods
     */
    public function testPatchUserToUserReturnsError(): void
    {
        $payload = [
            'property' => 'username',
            'value' => 'testUsername'
        ];
        $user = $this->createTestUser(
            'test@email.com',
            'testUsername',
            'correctPass',
            true
        );
        $target = $this->createTestUser(
            'testa@email.com',
            'testaUsername',
            'correctPass',
            true
        );
        $token = $this->createTestJwt($user->getEmail());

        $this->client->request(
            'PATCH',
            '/api/user/'.$target->getId(),
            [],
            [],
            [
                'HTTP_AUTHORIZATION' => "Bearer $token",
                'CONTENT_TYPE' => 'application/json',
                'HTTP_ACCEPT'  => 'application/json',
            ],
            json_encode($payload)
        );

        $this->assertResponseStatusCodeSame(403);
        $responseContent = $this->client->getResponse()->getContent();
        $data = json_decode($responseContent, true);
        $this->assertIsArray($data);
        $this->assertArrayHasKey('data', $data);
        $this->assertEmpty($data['data']);
        $this->assertArrayHasKey('error', $data);
        $this->assertArrayHasKey('message', $data['error']);
        $this->assertEquals('ACCESS_DENIED', $data['error']['message']);
    }
    public function testPatchUserToAdminReturnsError(): void
    {
        $payload = [
            'property' => 'username',
            'value' => 'testUsername'
        ];
        $user = $this->createTestUser(
            'test@email.com',
            'testUsername',
            'correctPass',
            true
        );
        $target = $this->createTestUser(
            'testa@email.com',
            'testaUsername',
            'correctPass',
            true,
            UserRole::Admin
        );
        $token = $this->createTestJwt($user->getEmail());

        $this->client->request(
            'PATCH',
            '/api/user/'.$target->getId(),
            [],
            [],
            [
                'HTTP_AUTHORIZATION' => "Bearer $token",
                'CONTENT_TYPE' => 'application/json',
                'HTTP_ACCEPT'  => 'application/json',
            ],
            json_encode($payload)
        );

        $this->assertResponseStatusCodeSame(403);
        $responseContent = $this->client->getResponse()->getContent();
        $data = json_decode($responseContent, true);
        $this->assertIsArray($data);
        $this->assertArrayHasKey('data', $data);
        $this->assertEmpty($data['data']);
        $this->assertArrayHasKey('error', $data);
        $this->assertArrayHasKey('message', $data['error']);
        $this->assertEquals('ACCESS_DENIED', $data['error']['message']);
    }
    public function testPatchAdminToAdminReturnsError(): void
    {
        $payload = [
            'property' => 'username',
            'value' => 'testUsername'
        ];
        $user = $this->createTestUser(
            'test@email.com',
            'testUsername',
            'correctPass',
            true,
            UserRole::Admin
        );
        $target = $this->createTestUser(
            'testa@email.com',
            'testaUsername',
            'correctPass',
            true,
            UserRole::Admin
        );
        $token = $this->createTestJwt($user->getEmail());

        $this->client->request(
            'PATCH',
            '/api/user/'.$target->getId(),
            [],
            [],
            [
                'HTTP_AUTHORIZATION' => "Bearer $token",
                'CONTENT_TYPE' => 'application/json',
                'HTTP_ACCEPT'  => 'application/json',
            ],
            json_encode($payload)
        );

        $this->assertResponseStatusCodeSame(403);
        $responseContent = $this->client->getResponse()->getContent();
        $data = json_decode($responseContent, true);
        $this->assertIsArray($data);
        $this->assertArrayHasKey('data', $data);
        $this->assertEmpty($data['data']);
        $this->assertArrayHasKey('error', $data);
        $this->assertArrayHasKey('message', $data['error']);
        $this->assertEquals('ACCESS_DENIED', $data['error']['message']);
    }
    public function testPatchValidUserWithNewUsernameReturnsUpdatedUser(): void
    {
        $payload = [
            'property' => 'username',
            'value' => 'newUsername'
        ];
        $user = $this->createTestUser(
            'test@email.com',
            'testUsername',
            'correctPass',
            true
        );
        $token = $this->createTestJwt($user->getEmail());

        $this->client->request(
            'PATCH',
            '/api/user/'.$user->getId(),
            [],
            [],
            [
                'HTTP_AUTHORIZATION' => "Bearer $token",
                'CONTENT_TYPE' => 'application/json',
                'HTTP_ACCEPT'  => 'application/json',
            ],
            json_encode($payload)
        );

        $this->assertResponseIsSuccessful();
        $responseContent = $this->client->getResponse()->getContent();
        $data = json_decode($responseContent, true);
        $this->assertIsArray($data);
        $this->assertArrayHasKey('error', $data);
        $this->assertEmpty($data['error']);
        $this->assertArrayHasKey('data', $data);
        $this->assertNotEmpty($data['data']);
        $this->assertArrayHasKey('user', $data['data']);
        $this->assertArrayHasKey('username', $data['data']['user']);
        $this->assertEquals($data['data']['user']['username'], $payload['value']);
    }
    public function testPatchValidUserWithNewEmailReturnsUpdatedUser(): void
    {
        $payload = [
            'property' => 'email',
            'value' => 'new@email.com'
        ];
        $user = $this->createTestUser(
            'test@email.com',
            'testUsername',
            'correctPass',
            true
        );
        $token = $this->createTestJwt($user->getEmail());

        $this->client->request(
            'PATCH',
            '/api/user/'.$user->getId(),
            [],
            [],
            [
                'HTTP_AUTHORIZATION' => "Bearer $token",
                'CONTENT_TYPE' => 'application/json',
                'HTTP_ACCEPT'  => 'application/json',
            ],
            json_encode($payload)
        );

        $this->assertResponseIsSuccessful();
        $responseContent = $this->client->getResponse()->getContent();
        $data = json_decode($responseContent, true);
        $this->assertIsArray($data);
        $this->assertArrayHasKey('error', $data);
        $this->assertEmpty($data['error']);
        $this->assertArrayHasKey('data', $data);
        $this->assertNotEmpty($data['data']);
        $this->assertArrayHasKey('user', $data['data']);
        $this->assertArrayHasKey('email', $data['data']['user']);
        $this->assertEquals($data['data']['user']['email'], $payload['value']);
    }
    public function testPatchAfterEmailChangeOldTokenReturnsError(): void
    {
        $payload = [
            'property' => 'email',
            'value' => 'new@email.com'
        ];
        $user = $this->createTestUser(
            'test@email.com',
            'testUsername',
            'correctPass',
            true
        );
        $token = $this->createTestJwt($user->getEmail());

        $this->client->request(
            'PATCH',
            '/api/user/'.$user->getId(),
            [],
            [],
            [
                'HTTP_AUTHORIZATION' => "Bearer $token",
                'CONTENT_TYPE' => 'application/json',
                'HTTP_ACCEPT'  => 'application/json',
            ],
            json_encode($payload)
        );

        $this->assertResponseIsSuccessful();

        // try the same request with the old token (and old email)
        $this->client->request(
            'PATCH',
            '/api/user/'.$user->getId(),
            [],
            [],
            [
                'HTTP_AUTHORIZATION' => "Bearer $token",
                'CONTENT_TYPE' => 'application/json',
                'HTTP_ACCEPT'  => 'application/json',
            ],
            json_encode($payload)
        );    

        $this->assertResponseStatusCodeSame(401);
        
        $responseContent = $this->client->getResponse()->getContent();
        $data = json_decode($responseContent, true);
        $this->assertIsArray($data);
        $this->assertArrayHasKey('data', $data);
        $this->assertEmpty($data['data']);
        $this->assertArrayHasKey('error', $data);
        $this->assertNotEmpty($data['error']);
        $this->assertEquals('AUTH_ERROR', $data['error']['message']);
    }
    public function testPatchValidUserWithUsedEmailReturnsError(): void
    {
        $unique = 'new@email.com';
        $payload = [
            'property' => 'email',
            'value' => $unique
        ];
        $user = $this->createTestUser(
            'test@email.com',
            'testUsername',
            'correctPass',
            true
        );
        $target = $this->createTestUser(
            $unique,
            'testUsername',
            'correctPass',
            true
        );
        $token = $this->createTestJwt($user->getEmail());

        $this->client->request(
            'PATCH',
            '/api/user/'.$user->getId(),
            [],
            [],
            [
                'HTTP_AUTHORIZATION' => "Bearer $token",
                'CONTENT_TYPE' => 'application/json',
                'HTTP_ACCEPT'  => 'application/json',
            ],
            json_encode($payload)
        );

        $this->assertResponseStatusCodeSame(409);
        $responseContent = $this->client->getResponse()->getContent();
        $data = json_decode($responseContent, true);
        $this->assertIsArray($data);
        $this->assertArrayHasKey('data', $data);
        $this->assertEmpty($data['data']);
        $this->assertArrayHasKey('error', $data);
        $this->assertArrayHasKey('message', $data['error']);
        $this->assertEquals('UNIQUE_VIOLATION', $data['error']['message']);
    }
    public function testPatchValidUserWithUnsupportedPropertyReturnsError(): void
    {
        $payload = [
            'property' => 'usar',
            'value' => 'newVal'
        ];
        $user = $this->createTestUser(
            'test@email.com',
            'testUsername',
            'correctPass',
            true
        );
        $token = $this->createTestJwt($user->getEmail());

        $this->client->request(
            'PATCH',
            '/api/user/'.$user->getId(),
            [],
            [],
            [
                'HTTP_AUTHORIZATION' => "Bearer $token",
                'CONTENT_TYPE' => 'application/json',
                'HTTP_ACCEPT'  => 'application/json',
            ],
            json_encode($payload)
        );

        $this->assertResponseStatusCodeSame(403);
        $responseContent = $this->client->getResponse()->getContent();
        $data = json_decode($responseContent, true);
        $this->assertIsArray($data);
        $this->assertArrayHasKey('data', $data);
        $this->assertEmpty($data['data']);
        $this->assertArrayHasKey('error', $data);
        $this->assertArrayHasKey('message', $data['error']);
        $this->assertEquals('FORBIDDEN_PROPERTY', $data['error']['message']);
    }
    public function testPatchValidUserWithBadOrEmptyValueReturnsError(): void
    {
        $payload = [
            'property' => 'username',
            'value' => null
        ];
        $user = $this->createTestUser(
            'test@email.com',
            'testUsername',
            'correctPass',
            true
        );
        $token = $this->createTestJwt($user->getEmail());

        $this->client->request(
            'PATCH',
            '/api/user/'.$user->getId(),
            [],
            [],
            [
                'HTTP_AUTHORIZATION' => "Bearer $token",
                'CONTENT_TYPE' => 'application/json',
                'HTTP_ACCEPT'  => 'application/json',
            ],
            json_encode($payload)
        );

        $this->assertResponseStatusCodeSame(403);
        $responseContent = $this->client->getResponse()->getContent();
        $data = json_decode($responseContent, true);
        $this->assertIsArray($data);
        $this->assertArrayHasKey('data', $data);
        $this->assertEmpty($data['data']);
        $this->assertArrayHasKey('error', $data);
        $this->assertArrayHasKey('message', $data['error']);
        $this->assertEquals('BAD_VALUE_TYPE', $data['error']['message']);
    }

    /**
     * delete() testing methods
     */
    public function testDeleteUserToUserReturnsError(): void
    {
        $user = $this->createTestUser(
            'test@email.com',
            'testUsername',
            'correctPass',
            true
        );
        $target = $this->createTestUser(
            'testa@email.com',
            'testaUsername',
            'correctPass',
            true
        );
        $token = $this->createTestJwt($user->getEmail());

        $this->client->request(
            'DELETE',
            '/api/user/'.$target->getId(),
            [],
            [],
            [
                'HTTP_AUTHORIZATION' => "Bearer $token",
                'CONTENT_TYPE' => 'application/json',
                'HTTP_ACCEPT'  => 'application/json',
            ],
        );

        $this->assertResponseStatusCodeSame(403);
        $responseContent = $this->client->getResponse()->getContent();
        $data = json_decode($responseContent, true);
        $this->assertIsArray($data);
        $this->assertArrayHasKey('data', $data);
        $this->assertEmpty($data['data']);
        $this->assertArrayHasKey('error', $data);
        $this->assertArrayHasKey('message', $data['error']);
        $this->assertEquals('ACCESS_DENIED', $data['error']['message']);
    }
    public function testDeleteUserToAdminReturnsError(): void
    {
        $user = $this->createTestUser(
            'test@email.com',
            'testUsername',
            'correctPass',
            true
        );
        $target = $this->createTestUser(
            'testa@email.com',
            'testaUsername',
            'correctPass',
            true,
            UserRole::Admin
        );
        $token = $this->createTestJwt($user->getEmail());

        $this->client->request(
            'DELETE',
            '/api/user/'.$target->getId(),
            [],
            [],
            [
                'HTTP_AUTHORIZATION' => "Bearer $token",
                'CONTENT_TYPE' => 'application/json',
                'HTTP_ACCEPT'  => 'application/json',
            ],
        );

        $this->assertResponseStatusCodeSame(403);
        $responseContent = $this->client->getResponse()->getContent();
        $data = json_decode($responseContent, true);
        $this->assertIsArray($data);
        $this->assertArrayHasKey('data', $data);
        $this->assertEmpty($data['data']);
        $this->assertArrayHasKey('error', $data);
        $this->assertArrayHasKey('message', $data['error']);
        $this->assertEquals('ACCESS_DENIED', $data['error']['message']);
    }
    public function testDeleteAdminToAdminReturnsError(): void
    {
        $user = $this->createTestUser(
            'test@email.com',
            'testUsername',
            'correctPass',
            true,
            UserRole::Admin
        );
        $target = $this->createTestUser(
            'testa@email.com',
            'testaUsername',
            'correctPass',
            true,
            UserRole::Admin
        );
        $token = $this->createTestJwt($user->getEmail());

        $this->client->request(
            'DELETE',
            '/api/user/'.$target->getId(),
            [],
            [],
            [
                'HTTP_AUTHORIZATION' => "Bearer $token",
                'CONTENT_TYPE' => 'application/json',
                'HTTP_ACCEPT'  => 'application/json',
            ],
        );

        $this->assertResponseStatusCodeSame(403);
        $responseContent = $this->client->getResponse()->getContent();
        $data = json_decode($responseContent, true);
        $this->assertIsArray($data);
        $this->assertArrayHasKey('data', $data);
        $this->assertEmpty($data['data']);
        $this->assertArrayHasKey('error', $data);
        $this->assertArrayHasKey('message', $data['error']);
        $this->assertEquals('ACCESS_DENIED', $data['error']['message']);
    }
    public function testDeleteBadUserReturnsError(): void
    {
        $user = $this->createTestUser(
            'test@email.com',
            'testUsername',
            'correctPass',
            true
        );
        $token = $this->createTestJwt($user->getEmail());

        $this->client->request(
            'DELETE',
            '/api/user/66666',
            [],
            [],
            [
                'HTTP_AUTHORIZATION' => "Bearer $token",
                'CONTENT_TYPE' => 'application/json',
                'HTTP_ACCEPT'  => 'application/json',
            ],
        );

        $this->assertResponseStatusCodeSame(404);
        $responseContent = $this->client->getResponse()->getContent();
        $data = json_decode($responseContent, true);
        $this->assertIsArray($data);
        $this->assertArrayHasKey('data', $data);
        $this->assertEmpty($data['data']);
        $this->assertArrayHasKey('error', $data);
        $this->assertArrayHasKey('message', $data['error']);
        $this->assertEquals('NOT_FOUND', $data['error']['message']);
    }
    public function testDeleteValidUserReturnsSuccess(): void
    {
        $user = $this->createTestUser(
            'test@email.com',
            'testUsername',
            'correctPass',
            true
        );
        $token = $this->createTestJwt($user->getEmail());

        $this->client->request(
            'DELETE',
            '/api/user/'.$user->getId(),
            [],
            [],
            [
                'HTTP_AUTHORIZATION' => "Bearer $token",
                'CONTENT_TYPE' => 'application/json',
                'HTTP_ACCEPT'  => 'application/json',
            ],
        );

        $this->assertResponseIsSuccessful();
        $responseContent = $this->client->getResponse()->getContent();
        $data = json_decode($responseContent, true);
        $this->assertIsArray($data);
        $this->assertArrayHasKey('error', $data);
        $this->assertEmpty($data['error']);
        $this->assertArrayHasKey('data', $data);
        $this->assertEmpty($data['data']);

        $userRepository = $this->entityManager->getRepository(User::class);
        $result = $userRepository->findOneBy(['email' => $user->getEmail()]);
        $this->assertNull($result);
    }
    
    /**
     * suspend() testing methods
     */
    public function testSuspendUserToUserReturnsError(): void
    {
        $user = $this->createTestUser(
            'test@email.com',
            'testUsername',
            'correctPass',
            true
        );
        $target = $this->createTestUser(
            'testa@email.com',
            'testaUsername',
            'correctPass',
            true
        );
        $token = $this->createTestJwt($user->getEmail());

        $this->client->request(
            'POST',
            '/api/user/'.$target->getId().'/suspend',
            [],
            [],
            [
                'HTTP_AUTHORIZATION' => "Bearer $token",
                'CONTENT_TYPE' => 'application/json',
                'HTTP_ACCEPT'  => 'application/json',
            ],
        );

        $this->assertResponseStatusCodeSame(403);
        $responseContent = $this->client->getResponse()->getContent();
        $data = json_decode($responseContent, true);
        $this->assertIsArray($data);
        $this->assertArrayHasKey('data', $data);
        $this->assertEmpty($data['data']);
        $this->assertArrayHasKey('error', $data);
        $this->assertArrayHasKey('message', $data['error']);
        $this->assertEquals('ACCESS_DENIED', $data['error']['message']);
    }
    public function testSuspendUserToAdminReturnsError(): void
    {
        $user = $this->createTestUser(
            'test@email.com',
            'testUsername',
            'correctPass',
            true
        );
        $target = $this->createTestUser(
            'testa@email.com',
            'testaUsername',
            'correctPass',
            true,
            UserRole::Admin
        );
        $token = $this->createTestJwt($user->getEmail());

        $this->client->request(
            'POST',
            '/api/user/'.$target->getId().'/suspend',
            [],
            [],
            [
                'HTTP_AUTHORIZATION' => "Bearer $token",
                'CONTENT_TYPE' => 'application/json',
                'HTTP_ACCEPT'  => 'application/json',
            ],
        );

        $this->assertResponseStatusCodeSame(403);
        $responseContent = $this->client->getResponse()->getContent();
        $data = json_decode($responseContent, true);
        $this->assertIsArray($data);
        $this->assertArrayHasKey('data', $data);
        $this->assertEmpty($data['data']);
        $this->assertArrayHasKey('error', $data);
        $this->assertArrayHasKey('message', $data['error']);
        $this->assertEquals('ACCESS_DENIED', $data['error']['message']);
    }
    public function testSuspendAdminToAdminReturnsError(): void
    {
        $user = $this->createTestUser(
            'test@email.com',
            'testUsername',
            'correctPass',
            true,
            UserRole::Admin
        );
        $target = $this->createTestUser(
            'testa@email.com',
            'testaUsername',
            'correctPass',
            true,
            UserRole::Admin
        );
        $token = $this->createTestJwt($user->getEmail());

        $this->client->request(
            'POST',
            '/api/user/'.$target->getId().'/suspend',
            [],
            [],
            [
                'HTTP_AUTHORIZATION' => "Bearer $token",
                'CONTENT_TYPE' => 'application/json',
                'HTTP_ACCEPT'  => 'application/json',
            ],
        );

        $this->assertResponseStatusCodeSame(403);
        $responseContent = $this->client->getResponse()->getContent();
        $data = json_decode($responseContent, true);
        $this->assertIsArray($data);
        $this->assertArrayHasKey('data', $data);
        $this->assertEmpty($data['data']);
        $this->assertArrayHasKey('error', $data);
        $this->assertArrayHasKey('message', $data['error']);
        $this->assertEquals('ACCESS_DENIED', $data['error']['message']);
    }
    public function testSuspendBadUserReturnsError(): void
    {
        $user = $this->createTestUser(
            'test@email.com',
            'testUsername',
            'correctPass',
            true,
            UserRole::Admin
        );
        $token = $this->createTestJwt($user->getEmail());

        $this->client->request(
            'POST',
            '/api/user/66666666/suspend',
            [],
            [],
            [
                'HTTP_AUTHORIZATION' => "Bearer $token",
                'CONTENT_TYPE' => 'application/json',
                'HTTP_ACCEPT'  => 'application/json',
            ],
        );

        $this->assertResponseStatusCodeSame(404);
        $responseContent = $this->client->getResponse()->getContent();
        $data = json_decode($responseContent, true);
        $this->assertIsArray($data);
        $this->assertArrayHasKey('data', $data);
        $this->assertEmpty($data['data']);
        $this->assertArrayHasKey('error', $data);
        $this->assertArrayHasKey('message', $data['error']);
        $this->assertEquals('NOT_FOUND', $data['error']['message']);
    }
    public function testSuspendAlreadySuspendedReturnsSuccess(): void
    {
        
        $user = $this->createTestUser(
            'test@email.com',
            'testUsername',
            'correctPass',
            true,
            UserRole::Admin
        );
        $target = $this->createTestUser(
            'testa@email.com',
            'testaUsername',
            'correctPass',
            true,
        );
        $target->setSuspendedUntil(new \DateTimeImmutable('+10 minutes'));
        $this->entityManager->flush();
        $token = $this->createTestJwt($user->getEmail());

        $this->client->request(
            'POST',
            '/api/user/'.$target->getId().'/suspend',
            [],
            [],
            [
                'HTTP_AUTHORIZATION' => "Bearer $token",
                'CONTENT_TYPE' => 'application/json',
                'HTTP_ACCEPT'  => 'application/json',
            ],
            json_encode([
                'until' => (new \DateTimeImmutable('+10 minutes'))->format(\DateTimeInterface::ATOM)
            ])
        );
        
        $this->assertResponseIsSuccessful();
        $responseContent = $this->client->getResponse()->getContent();
        $data = json_decode($responseContent, true);
        $this->assertIsArray($data);
        $this->assertArrayHasKey('data', $data);
        $this->assertEmpty($data['data']);
        $this->assertArrayHasKey('error', $data);
        $this->assertEmpty($data['error']);

        $resultingUser = $this->entityManager->getRepository(User::class)->findOneBy(['email' => $target->getEmail()]);
        $this->assertEquals(true, $resultingUser->isSuspended());
    }
    public function testSuspendValidUserReturnsSuccess(): void
    {
        
        $user = $this->createTestUser(
            'test@email.com',
            'testUsername',
            'correctPass',
            true,
            UserRole::Admin
        );
        $target = $this->createTestUser(
            'testa@email.com',
            'testaUsername',
            'correctPass',
            true,
        );
        $token = $this->createTestJwt($user->getEmail());

        $this->client->request(
            'POST',
            '/api/user/'.$target->getId().'/suspend',
            [],
            [],
            [
                'HTTP_AUTHORIZATION' => "Bearer $token",
                'CONTENT_TYPE' => 'application/json',
                'HTTP_ACCEPT'  => 'application/json',
            ],
            json_encode([
                'until' => (new \DateTimeImmutable('+10 minutes'))->format(\DateTimeInterface::ATOM)
            ])
        );
        
        $this->assertResponseIsSuccessful();
        $responseContent = $this->client->getResponse()->getContent();
        $data = json_decode($responseContent, true);
        $this->assertIsArray($data);
        $this->assertArrayHasKey('data', $data);
        $this->assertEmpty($data['data']);
        $this->assertArrayHasKey('error', $data);
        $this->assertEmpty($data['error']);

        $resultingUser = $this->entityManager->getRepository(User::class)->findOneBy(['email' => $target->getEmail()]);
        $this->assertEquals(true, $resultingUser->isSuspended());
    }

    /**
     * unsuspend() testing methods
     */
    public function testUnsuspendUserToUserReturnsError(): void
    {
        $user = $this->createTestUser(
            'test@email.com',
            'testUsername',
            'correctPass',
            true
        );
        $target = $this->createTestUser(
            'testa@email.com',
            'testaUsername',
            'correctPass',
            true
        );
        $token = $this->createTestJwt($user->getEmail());

        $this->client->request(
            'POST',
            '/api/user/'.$target->getId().'/unsuspend',
            [],
            [],
            [
                'HTTP_AUTHORIZATION' => "Bearer $token",
                'CONTENT_TYPE' => 'application/json',
                'HTTP_ACCEPT'  => 'application/json',
            ],
        );

        $this->assertResponseStatusCodeSame(403);
        $responseContent = $this->client->getResponse()->getContent();
        $data = json_decode($responseContent, true);
        $this->assertIsArray($data);
        $this->assertArrayHasKey('data', $data);
        $this->assertEmpty($data['data']);
        $this->assertArrayHasKey('error', $data);
        $this->assertArrayHasKey('message', $data['error']);
        $this->assertEquals('ACCESS_DENIED', $data['error']['message']);
    }
    public function testUnsuspendUserToAdminReturnsError(): void
    {
        $user = $this->createTestUser(
            'test@email.com',
            'testUsername',
            'correctPass',
            true
        );
        $target = $this->createTestUser(
            'testa@email.com',
            'testaUsername',
            'correctPass',
            true,
            UserRole::Admin
        );
        $token = $this->createTestJwt($user->getEmail());

        $this->client->request(
            'POST',
            '/api/user/'.$target->getId().'/unsuspend',
            [],
            [],
            [
                'HTTP_AUTHORIZATION' => "Bearer $token",
                'CONTENT_TYPE' => 'application/json',
                'HTTP_ACCEPT'  => 'application/json',
            ],
        );

        $this->assertResponseStatusCodeSame(403);
        $responseContent = $this->client->getResponse()->getContent();
        $data = json_decode($responseContent, true);
        $this->assertIsArray($data);
        $this->assertArrayHasKey('data', $data);
        $this->assertEmpty($data['data']);
        $this->assertArrayHasKey('error', $data);
        $this->assertArrayHasKey('message', $data['error']);
        $this->assertEquals('ACCESS_DENIED', $data['error']['message']);
    }
    public function testUnsuspendAdminToAdminReturnsError(): void
    {
        $user = $this->createTestUser(
            'test@email.com',
            'testUsername',
            'correctPass',
            true,
            UserRole::Admin
        );
        $target = $this->createTestUser(
            'testa@email.com',
            'testaUsername',
            'correctPass',
            true,
            UserRole::Admin
        );
        $token = $this->createTestJwt($user->getEmail());

        $this->client->request(
            'POST',
            '/api/user/'.$target->getId().'/unsuspend',
            [],
            [],
            [
                'HTTP_AUTHORIZATION' => "Bearer $token",
                'CONTENT_TYPE' => 'application/json',
                'HTTP_ACCEPT'  => 'application/json',
            ],
        );

        $this->assertResponseStatusCodeSame(403);
        $responseContent = $this->client->getResponse()->getContent();
        $data = json_decode($responseContent, true);
        $this->assertIsArray($data);
        $this->assertArrayHasKey('data', $data);
        $this->assertEmpty($data['data']);
        $this->assertArrayHasKey('error', $data);
        $this->assertArrayHasKey('message', $data['error']);
        $this->assertEquals('ACCESS_DENIED', $data['error']['message']);
    }
    public function testUnsuspendBadUserReturnsError(): void
    {
        $user = $this->createTestUser(
            'test@email.com',
            'testUsername',
            'correctPass',
            true,
            UserRole::Admin
        );
        $token = $this->createTestJwt($user->getEmail());

        $this->client->request(
            'POST',
            '/api/user/66666666/unsuspend',
            [],
            [],
            [
                'HTTP_AUTHORIZATION' => "Bearer $token",
                'CONTENT_TYPE' => 'application/json',
                'HTTP_ACCEPT'  => 'application/json',
            ],
        );

        $this->assertResponseStatusCodeSame(404);
        $responseContent = $this->client->getResponse()->getContent();
        $data = json_decode($responseContent, true);
        $this->assertIsArray($data);
        $this->assertArrayHasKey('data', $data);
        $this->assertEmpty($data['data']);
        $this->assertArrayHasKey('error', $data);
        $this->assertArrayHasKey('message', $data['error']);
        $this->assertEquals('NOT_FOUND', $data['error']['message']);
    }
    public function testUnsuspendAlreadyUnsuspendedReturnsSuccess(): void
    {
        
        $user = $this->createTestUser(
            'test@email.com',
            'testUsername',
            'correctPass',
            true,
            UserRole::Admin
        );
        $target = $this->createTestUser(
            'testa@email.com',
            'testaUsername',
            'correctPass',
            true,
        );
        $token = $this->createTestJwt($user->getEmail());

        $this->client->request(
            'POST',
            '/api/user/'.$target->getId().'/unsuspend',
            [],
            [],
            [
                'HTTP_AUTHORIZATION' => "Bearer $token",
                'CONTENT_TYPE' => 'application/json',
                'HTTP_ACCEPT'  => 'application/json',
            ],
        );
        
        $this->assertResponseIsSuccessful();
        $responseContent = $this->client->getResponse()->getContent();
        $data = json_decode($responseContent, true);
        $this->assertIsArray($data);
        $this->assertArrayHasKey('data', $data);
        $this->assertEmpty($data['data']);
        $this->assertArrayHasKey('error', $data);
        $this->assertEmpty($data['error']);

        $resultingUser = $this->entityManager->getRepository(User::class)->findOneBy(['email' => $target->getEmail()]);
        $this->assertEquals(false, $resultingUser->isSuspended());
    }
    public function testUnsuspendValidUserReturnsSuccess(): void
    {
        $user = $this->createTestUser(
            'test@email.com',
            'testUsername',
            'correctPass',
            true,
            UserRole::Admin
        );
        $target = $this->createTestUser(
            'testa@email.com',
            'testaUsername',
            'correctPass',
            true,
        );
        $target->setSuspendedUntil(new \DateTimeImmutable('+10 minutes'));
        $this->entityManager->flush();
        $token = $this->createTestJwt($user->getEmail());

        $this->client->request(
            'POST',
            '/api/user/'.$target->getId().'/unsuspend',
            [],
            [],
            [
                'HTTP_AUTHORIZATION' => "Bearer $token",
                'CONTENT_TYPE' => 'application/json',
                'HTTP_ACCEPT'  => 'application/json',
            ],
        );
        
        $this->assertResponseIsSuccessful();
        $responseContent = $this->client->getResponse()->getContent();
        $data = json_decode($responseContent, true);
        $this->assertIsArray($data);
        $this->assertArrayHasKey('data', $data);
        $this->assertEmpty($data['data']);
        $this->assertArrayHasKey('error', $data);
        $this->assertEmpty($data['error']);

        $resultingUser = $this->entityManager->getRepository(User::class)->findOneBy(['email' => $target->getEmail()]);
        $this->assertEquals(false, $resultingUser->isSuspended());
    }
    /* 
     * refresh() testing methods
     */
    public function testRefreshReturnsNewValidToken(): void
    {
        $user = $this->createTestUser(
            'test@email.com',
            'testUsername',
            'correctPass',
            true
        );
        $token = $this->createTestJwt($user->getEmail());

        $this->client->request(
            'POST',
            '/api/user/refresh',
            [],
            [],
            [
                'HTTP_AUTHORIZATION' => "Bearer $token",
                'CONTENT_TYPE' => 'application/json',
                'HTTP_ACCEPT'  => 'application/json',
            ],
        );

        $this->assertResponseIsSuccessful();
        $responseContent = $this->client->getResponse()->getContent();
        $data = json_decode($responseContent, true);
        $this->assertIsArray($data);
        $this->assertArrayHasKey('error', $data);
        $this->assertEmpty($data['error']);
        $this->assertArrayHasKey('data', $data);
        $this->assertNotEmpty($data['data']);
        $this->assertArrayHasKey('token', $data['data']);
        $this->assertNotEmpty($data['data']['token']);

        $decoded = JWT::decode($token, new Key($this->secret, $this->algorithm));
        $this->assertNotNull($decoded);
        $result = $this->entityManager->getRepository(User::class)->findOneBy(['email' => $decoded->sub]);
        $this->assertEquals($user->getUsername(), $result->getUsername());
        $this->assertEquals($user->getEmail(), $result->getEmail());
    }
    /**
     * Helper method to create a test user
     */
    private function createTestUser(
        string $email,
        string $username,
        string $password,
        bool $activated = false,
        UserRole $role = UserRole::User
    ): User {
        $user = new User($role);
        $user->setEmail($email);
        $user->setUsername($username);
        $user->setPassword($this->passwordHasher->hashPassword($user, $password));
        if ($activated) {
            $user->activate();
		}

        $this->entityManager->persist($user);
        $this->entityManager->flush();
        return $user;
    }
    /**
     * Clean database tables
     */
    private function cleanDatabase(): void
    {
        $connection = $this->entityManager->getConnection();

        // For PostgreSQL, we need to use TRUNCATE with CASCADE
        try {
            $connection->executeStatement('TRUNCATE TABLE token, users RESTART IDENTITY CASCADE');
        } catch (\Exception $e) {
            // Fallback to DELETE if TRUNCATE fails
            $connection->executeStatement('DELETE FROM token');
            $connection->executeStatement('DELETE FROM users');
        }

        $this->entityManager->clear();
    }
}
