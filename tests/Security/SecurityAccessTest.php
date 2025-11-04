<?php

namespace App\Tests\Security;

use App\Entity\User;
use App\Enum\UserRole;
use Doctrine\ORM\EntityManagerInterface;
use Firebase\JWT\JWT;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
/**
 * @group integration
 * @group security
 *
 * Tests that all protected endpoints enforce user status checks globally.
 * This ensures that inactive and suspended users cannot access any authenticated endpoint,
 * regardless of their role or permissions.
 *
 * These tests verify the security layer (UserChecker, firewall) is working correctly.
 * Individual endpoint tests should NOT duplicate these checks; they should focus on
 * business logic and authorization rules specific to each action.
 */
final class SecurityAccessTest extends WebTestCase
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
    protected function tearDown(): void
    {
        $this->cleanDatabase();
        parent::tearDown();
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

    public static function protectedEndpoints(): array
    {
        return [
            ['GET', '/api/user'],
            ['GET', '/api/user/{id}'],
            ['PATCH', '/api/user/{id}'],
            ['DELETE', '/api/user/{id}'],
            ['POST', '/api/user/refresh'],
        ];
    }

    #[DataProvider('protectedEndpoints')]
    public function testInactiveUserCannotAccessEndpoint(string $method, string $endpoint): void
    {
        // Arrange
        $inactiveUser = $this->createTestUser(
            'inactive@email.com',
            'inactiveUser',
            'password123',
            false
        );
        $token = $this->createTestJwt($inactiveUser->getEmail());

        // Act - dynamically uses the method and endpoint from data provider
        $this->client->request(
            $method,
            str_replace('{id}', $inactiveUser->getId(), $endpoint),
            [],
            [],
            [
                'HTTP_AUTHORIZATION' => "Bearer $token",
                'CONTENT_TYPE' => 'application/json',
                'HTTP_ACCEPT'  => 'application/json',
            ]
        );

        // Assert - same for all endpoints
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

    #[DataProvider('protectedEndpoints')]
    public function testSuspendedUserCannotAccessEndpoint(string $method, string $endpoint): void
    {
        // Arrange
        $user = $this->createTestUser(
            'test@email.com',
            'testUser',
            'password123',
            true
        );
        $token = $this->createTestJwt($user->getEmail());
        $user->setSuspendedUntil(new \DateTimeImmutable('+10 minutes'));
        $this->entityManager->flush();

        // Act - dynamically uses the method and endpoint from data provider
        $this->client->request(
            $method,
            str_replace('{id}', $user->getId(), $endpoint),
            [],
            [],
            [
                'HTTP_AUTHORIZATION' => "Bearer $token",
                'CONTENT_TYPE' => 'application/json',
                'HTTP_ACCEPT'  => 'application/json',
            ]
        );

        // Assert - same for all endpoints
        $this->assertResponseStatusCodeSame(403);
        
        $responseContent = $this->client->getResponse()->getContent();
        $data = json_decode($responseContent, true);
        $this->assertIsArray($data);
        $this->assertArrayHasKey('data', $data);
        $this->assertEmpty($data['data']);
        $this->assertArrayHasKey('error', $data);
        $this->assertNotEmpty($data['error']);
        $this->assertEquals('AUTH_ERROR', $data['error']['message']);
    }

    #[DataProvider('protectedEndpoints')]
    public function testUnauthorizedUserCannotAccessEndpoint(string $method, string $endpoint): void
    {

        // Act - dynamically uses the method and endpoint from data provider
        $this->client->request(
            $method,
            str_replace('{id}', '6666666', $endpoint),
            [],
            [],
            [
                'CONTENT_TYPE' => 'application/json',
                'HTTP_ACCEPT'  => 'application/json',
            ]
        );

        // Assert - same for all endpoints
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

    #[DataProvider('protectedEndpoints')]
    public function testBadTokenCannotAccessEndpoint(string $method, string $endpoint): void
    {
        $this->client->request(
            $method,
            str_replace('{id}', '6666666', $endpoint),
            [],
            [],
            [
                'HTTP_AUTHORIZATION' => "Bearer BadToken",
                'CONTENT_TYPE' => 'application/json',
                'HTTP_ACCEPT'  => 'application/json',
            ]
        );

        $this->assertResponseStatusCodeSame(401);
        
        $responseContent = $this->client->getResponse()->getContent();
        $data = json_decode($responseContent, true);
        $this->assertIsArray($data);
        $this->assertArrayHasKey('data', $data);
        $this->assertEmpty($data['data']);
        $this->assertArrayHasKey('error', $data);
        $this->assertNotEmpty($data['error']);
        $this->assertEquals('TOKEN_UNEXPECTED_VALUE', $data['error']['message']);
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