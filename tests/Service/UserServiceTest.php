<?php
namespace Tests\Service;

use App\DTO\UserListFiltersDTO;
use App\Entity\User;
use App\Enum\TokenType;
use App\Enum\UserRole;
use App\Repository\UserRepository;
use App\Service\EmailService;
use App\Service\TokenService;
use App\Service\UserService;
use Doctrine\ORM\EntityManagerInterface;
use PHPUnit\Framework\MockObject\MockObject;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;

/**
 * @group integration
 */
final class UserServiceTest extends KernelTestCase
{

    private string $username    = 'johndoe';
    private string $email       = 'john@example.com';
    private string $password    = 'SecurePassword123!';

    private UserService $userService;
    private EntityManagerInterface $entityManager;
    private UserRepository $userRepository;
    private TokenService $tokenService;
    private UserPasswordHasherInterface $passwordHasher;
    private MockObject&EmailService $emailService;

    protected function setUp(): void
    {
        parent::setUp();
        
        self::bootKernel();
        $container = static::getContainer();
        
        $this->entityManager    = $container->get(EntityManagerInterface::class);
        $this->userRepository   = $container->get(UserRepository::class);
        $this->tokenService     = $container->get(TokenService::class);
        $this->passwordHasher   = $container->get(UserPasswordHasherInterface::class);
        $this->emailService     = $this->createMock(EmailService::class);
        
        $this->userService = new UserService(
            $this->entityManager,
            $this->tokenService,
            $this->userRepository,
            $this->passwordHasher,
            $this->emailService
        );
        
        // Clean database before each test
        $this->cleanDatabase();
    }

    protected function tearDown(): void
    {
        $this->cleanDatabase();
        parent::tearDown();
    }

    /**
     * get() testing methods
     */
    public function testGetWithValidIdReturnsUser(): void
    {
        // Arrange
        $username   = $this->username;
        $email      = $this->email;
        $password   = $this->password;
        $user       = $this->createTestUser($email, $username, $password);

        // Act
        $user = $this->userService->get($user->getId());

        // Assert
        $this->assertInstanceOf(User::class, $user);
        $this->assertSame($email, $user->getEmail());

    }

    /**
     * setUsername() testing methods
     */
    public function testSetUsernamePersistsChanges(): void
    {
        // Arrange
        $username   = $this->username;
        $newUsername = 'test_username';
        $email      = $this->email;
        $password   = $this->password;
        
        $user = $this->createTestUser($email, $username, $password, true);
        
        // Act
        $this->userService->setUsername($user, $newUsername);

        // Assert
        $this->entityManager->refresh($user);
        $this->assertEquals($newUsername, $user->getUsername());
    }

    /**
     * setEmail() testing methods
     */
    public function testSetEmailPersistsChanges(): void
    {
        // Arrange
        $username   = $this->username;
        $email      = $this->email;
        $newEmail   = 'new_email@example.com';
        $password   = $this->password;
        
        $user = $this->createTestUser($email, $username, $password, true);
        
        // Act
        $this->userService->setEmail($user, $newEmail);

        // Assert
        $this->entityManager->refresh($user);
        $this->assertEquals($newEmail, $user->getEmail());
    }
    public function testSetEmailWithDuplicateEmailReturnsError(): void
    {
        // Arrange
        $oldEmail   = 'test@email.com';
        $newEmail   = 'unique@example.com';
        
        $user = $this->createTestUser(
            $oldEmail,
            'testUsername',
            'correctPass',
            true
        );
        $target = $this->createTestUser(
            $newEmail,
            'testUsername2',
            'correctPass',
            true
        );
        
        // Act
        $this->expectException(\Doctrine\DBAL\Exception\UniqueConstraintViolationException::class);
        $this->userService->setEmail($user, $newEmail);

        // Assert
        $this->entityManager->refresh($user);
        $this->assertEquals($oldEmail, $user->getEmail());
    }

    /**
     * index() testing methods
     */
    public function testIndexReturnsFilteredUsers(): void
    {
        // Arrange
        $this->createTestUser('user1@example.com', 'user1', 'password', true, UserRole::User);
        $this->createTestUser('admin@example.com', 'admin', 'password', true, UserRole::Admin);
        $this->createTestUser('inactive@example.com', 'inactive', 'password', false, UserRole::User);

        $dto = new UserListFiltersDTO(
            isActivated: true
        );
        $filters = $dto->toArray();

        // Act
        $index = $this->userService->index($filters);
        $users = $index['users'];

        // Assert
        $this->assertIsArray($users);
        $this->assertCount(2, $users);
        $this->assertSame('user1@example.com', $users[0]['email']);
        $this->assertSame('admin@example.com', $users[1]['email']);
    }
    public function testIndexWithNoMatchesReturnsEmptyArray(): void
    {
        // Arrange
        $this->createTestUser('user1@example.com', 'user1', 'password', true, UserRole::User);
        $this->createTestUser('admin@example.com', 'admin', 'password', true, UserRole::Admin);

        $dto = new UserListFiltersDTO(
            isActivated: false
        );
        $filters = $dto->toArray();

        // Act
        $index = $this->userService->index($filters);
        $users = $index['users'];

        // Assert
        $this->assertIsArray($users);
        $this->assertEmpty($users);
        $this->assertCount(0, $users);
    }

    /**
     * create() testing methods
     */
    public function testCreateUserPersistsToDatabase(): void
    {
        $username   = $this->username;
        $email      = $this->email;
        $password   = $this->password;

        $this->emailService
            ->expects($this->once())
            ->method('sendWelcomeEmail');

        $result = $this->userService->create($username, $email, $password);

        $this->assertIsArray($result);
        $this->assertArrayHasKey('token', $result);
        $this->assertArrayHasKey('user', $result);
        $this->assertNotEmpty($result['token']);

        // Verify user is persisted in database
        $savedUser = $this->userRepository->findOneBy(['email' => $email]);
        $this->assertInstanceOf(User::class, $savedUser);
        $this->assertSame($username, $savedUser->getUsername());
        $this->assertSame($email, $savedUser->getEmail());
        $this->assertFalse($savedUser->isActivated());
        $this->assertTrue($this->passwordHasher->isPasswordValid($savedUser, $password));
        $this->assertContains(UserRole::User->value, $savedUser->getRoles());

        // Verify token is created and valid
        $user = $this->tokenService->verifyToken($result['token'], TokenType::ActivateAccount);
        $this->assertSame($savedUser->getId(), $user->getId());
    }
    public function testCreateAdminUserWithCorrectRole(): void
    {
        $username   = $this->username;
        $email      = $this->email;
        $password   = $this->password;
        $role       = UserRole::Admin;

        $this->emailService
            ->expects($this->once())
            ->method('sendWelcomeEmail');

        $result = $this->userService->create($username, $email, $password, $role);

        $savedUser = $this->userRepository->findOneBy(['email' => $email]);
        $this->assertInstanceOf(User::class, $savedUser);
		$this->assertContains(UserRole::User->value, $savedUser->getRoles());
		$this->assertContains(UserRole::Admin->value, $savedUser->getRoles());
    }
    public function testCreateUserWithDuplicateEmailThrowsException(): void
    {
        // Arrange
        $username   = $this->username;
        $email      = $this->email;
        $password   = $this->password;

        $this->createTestUser($email, $username, $password);

        $this->emailService
            ->expects($this->never())
            ->method('sendWelcomeEmail');

        // Act & Assert
        $this->expectException(\Exception::class);
        $this->userService->create('user2', $email, 'AnotherPassword123!');
    }

    /**
     * delete() testing methods
     */
    public function testDeleteRemovesUserFromDatabase(): void
    {
        // Arrange
        $username   = $this->username;
        $email      = $this->email;
        $password   = $this->password;
        $user       = $this->createTestUser($email, $username, $password);
        $id         = $user->getId();

        // Act
        $this->userService->delete($user);
        
        // Assert
        $deletedUser = $this->userRepository->find($id);
        $this->assertNull($deletedUser);
    }

    /**
     * suspend() testing methods
     */
    public function testSuspendSetsSuspensionDate(): void
    {
        // Arrange
        $username   = $this->username;
        $email      = $this->email;
        $password   = $this->password;
        $user       = $this->createTestUser($email, $username, $password, true);
        $date       = new \DateTimeImmutable('+10 minutes');
        
        // Act
        $this->userService->suspend($user, $date);

        // Assert
        $this->entityManager->refresh($user);
        $this->assertTrue($user->isSuspended());
        $this->assertEquals(
            $date->format('Y-m-d H:i:s'),
            $user->getSuspendedUntil()->format('Y-m-d H:i:s')
        );
    }

    /**
     * unsuspend() testing methods
     */
    public function testUnsuspendRemovesSuspensionDate(): void
    {
        // Arrange
        $username   = $this->username;
        $email      = $this->email;
        $password   = $this->password;
        $user       = $this->createTestUser($email, $username, $password, true);
        $date       = new \DateTimeImmutable();
        
        // Act
        $this->userService->unsuspend($user);

        // Assert
        $this->entityManager->refresh($user);
        $this->assertFalse($user->isSuspended());
        $this->assertNull($user->getSuspendedUntil());
    }

    /**
     * login() testing methods
     */
    public function testLoginWithValidCredentialsReturnsTokenAndUser(): void
    {
        // Arrange
        $username   = $this->username;
        $email      = $this->email;
        $password   = $this->password;

        $user = $this->createTestUser($email, $username, $password, true);

        // Act
        $result = $this->userService->login($user);

        // Assert
        $this->assertIsArray($result);
        $this->assertArrayHasKey('token', $result);
        $this->assertArrayHasKey('user', $result);
        $this->assertNotEmpty($result['token']);
        $this->assertSame($user->getId(), $result['user']['id']);
        $this->assertSame($email, $result['user']['email']);

        // Verify token is valid JWT
        $decodedUser = $this->tokenService->decodeSessionJwt($result['token']);
        $this->assertSame($user->getEmail(), $decodedUser->sub);
    }

    /**
     * activateAccount() testing methods
     */
    public function testActivateUserWithValidToken(): void
    {
        // Arrange
        $username   = $this->username;
        $email      = $this->email;
        $password   = $this->password;
        
        $user = $this->createTestUser($email, $username, $password, false);
        $token = $this->tokenService->createToken(TokenType::ActivateAccount, $user);

        // Act
        $this->userService->activateAccount($token);

        // Assert
        $this->entityManager->refresh($user);
        $this->assertTrue($user->isActivated());
    }

    /**
     * forgotPassword() testing methods
     */
    public function testForgotPasswordWithValidUserCreatesTokenAndSendsEmail(): void
    {
        // Arrange
        $username   = $this->username;
        $email      = $this->email;
        $password   = $this->password;
        
        $user = $this->createTestUser($email, $username, $password, true);

        $this->emailService
            ->expects($this->once())
            ->method('sendPasswordResetEmail');

        // Act
        $token = $this->userService->forgotPassword($email);

        // Assert
        $this->assertIsString($token);
        $this->assertNotEmpty($token);

        // Verify token is valid
        $tokenUser = $this->tokenService->verifyToken($token, TokenType::ForgotPassword);
        $this->assertSame($user->getId(), $tokenUser->getId());
    }
    public function testForgotPasswordWithInactiveUserReturnsNull(): void
    {
        // Arrange
        $username   = $this->username;
        $email      = $this->email;
        $password   = $this->password;
        
        $this->createTestUser($email, $username, $password, false); // Not activated

        $this->emailService
            ->expects($this->never())
            ->method('sendPasswordResetEmail');

        // Act
        $result = $this->userService->forgotPassword($email);

        // Assert
        $this->assertNull($result);
    }
    public function testForgotPasswordWithNonExistentUserReturnsNull(): void
    {
        // Arrange
        $email      = $this->email;

        $this->emailService
            ->expects($this->never())
            ->method('sendPasswordResetEmail');

        // Act
        $result = $this->userService->forgotPassword($email);

        // Assert
        $this->assertNull($result);
    }

    /**
     * resetPassword() testing methods
     */
    public function testResetPasswordUpdatesUserPassword(): void
    {
        // Arrange
        $username   = $this->username;
        $email      = $this->email;
        $password   = $this->password;
        $newPassword = 'NewPassword456!';
        
        $user = $this->createTestUser($email, $username, $password, true);
        
        // Create forgot password token
        $token = $this->tokenService->createToken(TokenType::ForgotPassword, $user);

        // Act
        $this->userService->resetPassword($token, $newPassword);

        // Assert
        $this->entityManager->refresh($user);
        $this->assertFalse($this->passwordHasher->isPasswordValid($user, $password));
        $this->assertTrue($this->passwordHasher->isPasswordValid($user, $newPassword));
    }
    public function testResetPasswordWithInvalidTokenThrowsException(): void
    {
        // Arrange
        $token      = 'invalid_token_123';
        $password   = $this->password;

        // Act & Assert
        $this->expectException(\Exception::class);
        $this->userService->resetPassword($token, $password);
    }

    /**
     * resendActivation() testing methods
     */
    public function testResendActivationWithInactiveUserCreatesNewToken(): void
    {
        // Arrange
        $username   = $this->username;
        $email      = $this->email;
        $password   = $this->password;
        
        $user = $this->createTestUser($email, $username, $password, false);

        $this->emailService
            ->expects($this->once())
            ->method('sendWelcomeEmail');

        // Act
        $token = $this->userService->resendActivation($email);

        // Assert
        $this->assertIsString($token);
        $this->assertNotEmpty($token);

        // Verify token is valid
        $tokenUser = $this->tokenService->verifyToken($token, TokenType::ActivateAccount);
        $this->assertSame($user->getId(), $tokenUser->getId());
    }
    public function testResendActivationWithActiveUserReturnsNull(): void
    {
        // Arrange
        $username   = $this->username;
        $email      = $this->email;
        $password   = $this->password;
        
        $this->createTestUser($email, $username, $password, true);

        $this->emailService
            ->expects($this->never())
            ->method('sendWelcomeEmail');

        // Act
        $result = $this->userService->resendActivation($email);

        // Assert
        $this->assertNull($result);
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