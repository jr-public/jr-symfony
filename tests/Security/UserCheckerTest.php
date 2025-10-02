<?php

namespace App\Tests\Security;

use App\Entity\User;
use App\Enum\UserRole;
use App\Exception\AuthException;
use App\Security\UserChecker;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;

/**
 * @group unit
 */
final class UserCheckerTest extends KernelTestCase
{
    private UserChecker $userChecker;
    private EntityManagerInterface $entityManager;
    private UserPasswordHasherInterface $passwordHasher;

    protected function setUp(): void
    {
        parent::setUp();
        
        self::bootKernel();
        $container = static::getContainer();
        
        $this->userChecker = new UserChecker();
        $this->entityManager = $container->get(EntityManagerInterface::class);
        $this->passwordHasher = $container->get(UserPasswordHasherInterface::class);
        
        // Clean database before each test
        $this->cleanDatabase();
    }

    protected function tearDown(): void
    {
        $this->cleanDatabase();
        parent::tearDown();
    }

    /**
     * checkPreAuth() testing methods
     */
    public function testCheckPreAuthWithValidUserPassesSuccessfully(): void
    {
        // Arrange
        $user = $this->createTestUser('test@email.com', 'testUser', 'password123');

        // Act & Assert
        $this->userChecker->checkPreAuth($user);
        
        // If no exception is thrown, the test passes
        $this->assertTrue(true);
    }

    public function testCheckPreAuthWithInvalidUserTypeThrowsException(): void
    {
        // Arrange
        $invalidUser = $this->createMock(\Symfony\Component\Security\Core\User\UserInterface::class);

        // Assert
        $this->expectException(AuthException::class);
        $this->expectExceptionMessage('AUTH_ERROR');
        $this->expectExceptionCode(500);

        // Act
        $this->userChecker->checkPreAuth($invalidUser);
    }

    /**
     * checkPostAuth() testing methods
     */
    public function testCheckPostAuthWithActivatedUserPassesSuccessfully(): void
    {
        // Arrange
        $user = $this->createTestUser('test@email.com', 'testUser', 'password123', true);

        // Act & Assert
        $this->userChecker->checkPostAuth($user);
        
        // If no exception is thrown, the test passes
        $this->assertTrue(true);
    }

    public function testCheckPostAuthWithInvalidUserTypeThrowsException(): void
    {
        // Arrange
        $invalidUser = $this->createMock(\Symfony\Component\Security\Core\User\UserInterface::class);

        // Assert
        $this->expectException(AuthException::class);
        $this->expectExceptionMessage('AUTH_ERROR');
        $this->expectExceptionCode(500);

        // Act
        $this->userChecker->checkPostAuth($invalidUser);
    }

    public function testCheckPostAuthWithInactiveUserThrowsException(): void
    {
        // Arrange
        $user = $this->createTestUser('test@email.com', 'testUser', 'password123', false);

        // Assert
        $this->expectException(AuthException::class);
        $this->expectExceptionMessage('AUTH_ERROR');
        $this->expectExceptionCode(401);

        // Act
        $this->userChecker->checkPostAuth($user);
    }

    public function testCheckPostAuthWithSuspendedUserThrowsException(): void
    {
        // Arrange
        $user = $this->createTestUser('test@email.com', 'testUser', 'password123', true);
        $suspension = new \DateTimeImmutable('+10 minutes');
        $user->setSuspendedUntil($suspension);
        $this->entityManager->flush();

        // Assert
        $this->expectException(AuthException::class);
        $this->expectExceptionMessage('AUTH_ERROR');
        $this->expectExceptionCode(403);

        // Act
        $this->userChecker->checkPostAuth($user);
    }

    public function testCheckPostAuthWithExpiredSuspensionPassesSuccessfully(): void
    {
        // Arrange
        $user = $this->createTestUser('test@email.com', 'testUser', 'password123', true);
        $expiredSuspension = new \DateTimeImmutable('-10 minutes');
        $user->setSuspendedUntil($expiredSuspension);
        $this->entityManager->flush();

        // Act & Assert
        $this->userChecker->checkPostAuth($user);
        
        // If no exception is thrown, the test passes
        $this->assertTrue(true);
    }

    public function testCheckPostAuthWithInactiveAndSuspendedUserThrowsInactiveException(): void
    {
        // Arrange
        $user = $this->createTestUser('test@email.com', 'testUser', 'password123', false);
        $suspension = new \DateTimeImmutable('+10 minutes');
        $user->setSuspendedUntil($suspension);
        $this->entityManager->flush();

        // Assert - Inactive check comes before suspended check
        $this->expectException(AuthException::class);
        $this->expectExceptionMessage('AUTH_ERROR');
        $this->expectExceptionCode(401);

        // Act
        $this->userChecker->checkPostAuth($user);
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