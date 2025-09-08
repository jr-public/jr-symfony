<?php
namespace Tests\Unit\Service;

use App\Entity\User;
use App\Enum\TokenType;
use App\Enum\UserRole;
use App\Repository\UserRepository;
use App\Service\EmailService;
use App\Service\TokenService;
use App\Service\UserService;
use Doctrine\ORM\EntityManagerInterface;
use PHPUnit\Framework\MockObject\MockObject;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;

final class UserServiceTest extends WebTestCase
{
    private UserService $userService;
    private MockObject&UserRepository $userRepositoryMock;
    private MockObject&EntityManagerInterface $entityManagerMock;
    private MockObject&TokenService $tokenServiceMock;
    private MockObject&EmailService $emailServiceMock;
    private MockObject&UserPasswordHasherInterface $passwordHasherMock;

    protected function setUp(): void
    {
        parent::setUp();
        $this->userRepositoryMock = $this->createMock(UserRepository::class);
        $this->entityManagerMock = $this->createMock(EntityManagerInterface::class);
        $this->tokenServiceMock = $this->createMock(TokenService::class);
        $this->emailServiceMock = $this->createMock(EmailService::class);
        $this->passwordHasherMock = $this->createMock(UserPasswordHasherInterface::class);
        
        $this->userService = new UserService(
            $this->entityManagerMock,
            $this->tokenServiceMock,
            $this->userRepositoryMock,
            $this->passwordHasherMock,
            $this->emailServiceMock
        );
    }
    /**
     * Login testing methods
     */
	public function testLoginReturnsTokenAndUserData(): void
    {
        $userData = ['id' => 1, 'email' => 'test@example.com'];
        $userMock = $this->createMock(User::class);
        $userMock
            ->expects($this->once())
            ->method('toArray')
            ->willReturn($userData);
        $userMock
            ->expects($this->once())
            ->method('getEmail')
            ->willReturn($userData['email']);
        
        $token = 'mock_jwt_token_12345';
        $this->tokenServiceMock
            ->expects($this->once())
            ->method('createSessionJwt')
            ->willReturn($token);

        $result = $this->userService->login($userMock);
        
        $this->assertIsArray($result);
        $this->assertArrayHasKey('token', $result);
        $this->assertSame($token, $result['token']);
        $this->assertArrayHasKey('user', $result);
        $this->assertSame($userData, $result['user']);
    }
    public function testLoginWithTokenFailureThrowsException(): void
    {
        $userMock = $this->createMock(User::class);
        $userMock
            ->expects($this->once())
            ->method('getEmail')
            ->willReturn('email@test.com');
        
        $this->tokenServiceMock
            ->expects($this->once())
            ->method('createSessionJwt')
            ->willThrowException(new \Exception("test_jwt_error"));
        
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('test_jwt_error');

        $this->userService->login($userMock);
    }
    /**
     * Create testing methods
     */
    public function testCreateUserReturnsTokenAndUserData(): void
    {
        $username = "john";
        $email = "john@example.com";
        $plainPassword = "secret123";
        $hashedPassword = "hashed_secret";
        $token = "activation_token";

        // Expectations
        $this->passwordHasherMock
            ->expects($this->once())
            ->method('hashPassword')
            ->with($this->isInstanceOf(User::class), $plainPassword)
            ->willReturn($hashedPassword);

        $this->entityManagerMock
            ->expects($this->once())
            ->method('persist')
            ->with($this->isInstanceOf(User::class));

        $this->entityManagerMock
            ->expects($this->once())
            ->method('flush');

        $this->tokenServiceMock
            ->expects($this->once())
            ->method('createToken')
            ->with(TokenType::ActivateAccount, $this->isInstanceOf(User::class))
            ->willReturn($token);

        $this->emailServiceMock
            ->expects($this->once())
            ->method('sendWelcomeEmail')
            ->with($email, $username, $token);

        // Execute
        $result = $this->userService->create($username, $email, $plainPassword);
        
        // Assertions
        $this->assertIsArray($result);
        $this->assertArrayHasKey('token', $result);
        $this->assertArrayHasKey('user', $result);
        $this->assertEquals($token, $result['token']);
        $this->assertEquals($username, $result['user']['username']);
        $this->assertEquals($email, $result['user']['email']);
    }
    public function testCreateAdminHasCorrectRole(): void
    {
        $username = "john";
        $email = "john@example.com";
        $role = UserRole::Admin;
        $plainPassword = "secret123";
        $hashedPassword = "hashed_secret";
        $token = "activation_token";

        // Expectations
        $this->passwordHasherMock
            ->expects($this->once())
            ->method('hashPassword')
            ->with($this->isInstanceOf(User::class), $plainPassword)
            ->willReturn($hashedPassword);

        $this->entityManagerMock
            ->expects($this->once())
            ->method('persist')
            ->with($this->isInstanceOf(User::class));

        $this->entityManagerMock
            ->expects($this->once())
            ->method('flush');

        $this->tokenServiceMock
            ->expects($this->once())
            ->method('createToken')
            ->with(TokenType::ActivateAccount, $this->isInstanceOf(User::class))
            ->willReturn($token);

        $this->emailServiceMock
            ->expects($this->once())
            ->method('sendWelcomeEmail')
            ->with($email, $username, $token);

        // Execute
        $result = $this->userService->create($username, $email, $plainPassword, $role);
        
        // Assertions
        $this->assertIsArray($result);
        $this->assertArrayHasKey('token', $result);
        $this->assertArrayHasKey('user', $result);
        $this->assertEquals($token, $result['token']);
        $this->assertEquals($username, $result['user']['username']);
        $this->assertEquals($email, $result['user']['email']);
        $this->assertEquals([UserRole::User, $role], $result['user']['roles']);
    }
    public function testCreateOnPersistErrorThrowsException(): void
    {
        $username = "john";
        $email = "john@example.com";
        $plainPassword = "secret123";
        $hashedPassword = "hashed_secret";

        // Expectations
        $this->passwordHasherMock
            ->expects($this->once())
            ->method('hashPassword')
            ->with($this->isInstanceOf(User::class), $plainPassword)
            ->willReturn($hashedPassword);

        $this->entityManagerMock
            ->expects($this->once())
            ->method('persist')
            ->willThrowException(new \Exception('USER_CREATION_FAILED'));

        $this->entityManagerMock
            ->expects($this->never())
            ->method('flush');

        $this->tokenServiceMock
            ->expects($this->never())
            ->method('createToken');

        $this->emailServiceMock
            ->expects($this->never())
            ->method('sendWelcomeEmail');
        
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('USER_CREATION_FAILED');

        $this->userService->create($username, $email, $plainPassword);
    }
    /**
     * forgotPassword tests
     */
    public function testForgotPasswordReturnsTokenAndSendsEmail(): void
    {
        $email = "test@example.com";
        $username = "john";
        $token = "forgot_token";

        $userMock = $this->createMock(User::class);
        $userMock->expects($this->once())
            ->method('isActivated')
            ->willReturn(true);
        $userMock->expects($this->once())
            ->method('getEmail')
            ->willReturn($email);
        $userMock->expects($this->once())
            ->method('getUsername')
            ->willReturn($username);

        $this->userRepositoryMock
            ->expects($this->once())
            ->method('findOneBy')
            ->with(['email' => $email])
            ->willReturn($userMock);

        $this->tokenServiceMock
            ->expects($this->once())
            ->method('createToken')
            ->with(TokenType::ForgotPassword, $userMock)
            ->willReturn($token);

        $this->emailServiceMock
            ->expects($this->once())
            ->method('sendPasswordResetEmail')
            ->with($email, $username, $token);

        $result = $this->userService->forgotPassword($email);

        $this->assertSame($token, $result);
    }

    public function testForgotPasswordReturnsNullWhenUserNotFound(): void
    {
        $email = "missing@example.com";

        $this->userRepositoryMock
            ->expects($this->once())
            ->method('findOneBy')
            ->with(['email' => $email])
            ->willReturn(null);

        $this->tokenServiceMock
            ->expects($this->never())
            ->method('createToken');

        $this->emailServiceMock
            ->expects($this->never())
            ->method('sendPasswordResetEmail');

        $result = $this->userService->forgotPassword($email);

        $this->assertNull($result);
    }

    public function testForgotPasswordReturnsNullWhenUserNotActivated(): void
    {
        $email = "inactive@example.com";

        $userMock = $this->createMock(User::class);
        $userMock->expects($this->once())
            ->method('isActivated')
            ->willReturn(false);

        $this->userRepositoryMock
            ->expects($this->once())
            ->method('findOneBy')
            ->with(['email' => $email])
            ->willReturn($userMock);

        $this->tokenServiceMock
            ->expects($this->never())
            ->method('createToken');

        $this->emailServiceMock
            ->expects($this->never())
            ->method('sendPasswordResetEmail');

        $result = $this->userService->forgotPassword($email);

        $this->assertNull($result);
    }

    /**
     * resetPassword tests
     */
    public function testResetPasswordHashesPasswordAndFlushes(): void
    {
        $token = "reset_token";
        $plainPassword = "newSecret";
        $hashedPassword = "hashedNewSecret";

        $userMock = $this->createMock(User::class);
        $userMock->expects($this->once())
            ->method('setPassword')
            ->with($hashedPassword);

        $this->tokenServiceMock
            ->expects($this->once())
            ->method('verifyToken')
            ->with($token, TokenType::ForgotPassword)
            ->willReturn($userMock);

        $this->passwordHasherMock
            ->expects($this->once())
            ->method('hashPassword')
            ->with($userMock, $plainPassword)
            ->willReturn($hashedPassword);

        $this->entityManagerMock
            ->expects($this->once())
            ->method('flush');

        $this->userService->resetPassword($token, $plainPassword);
    }

    /**
     * resendActivation tests
     */
    public function testResendActivationReturnsTokenAndSendsEmail(): void
    {
        $email = "inactive@example.com";
        $username = "john";
        $token = "activation_token";

        $userMock = $this->createMock(User::class);
        $userMock->expects($this->once())
            ->method('isActivated')
            ->willReturn(false);
        $userMock->expects($this->once())
            ->method('getEmail')
            ->willReturn($email);
        $userMock->expects($this->once())
            ->method('getUsername')
            ->willReturn($username);

        $this->userRepositoryMock
            ->expects($this->once())
            ->method('findOneBy')
            ->with(['email' => $email])
            ->willReturn($userMock);

        $this->tokenServiceMock
            ->expects($this->once())
            ->method('createToken')
            ->with(TokenType::ActivateAccount, $userMock)
            ->willReturn($token);

        $this->emailServiceMock
            ->expects($this->once())
            ->method('sendWelcomeEmail')
            ->with($email, $username, $token);

        $result = $this->userService->resendActivation($email);

        $this->assertSame($token, $result);
    }

    public function testResendActivationReturnsNullWhenUserNotFound(): void
    {
        $email = "notfound@example.com";

        $this->userRepositoryMock
            ->expects($this->once())
            ->method('findOneBy')
            ->with(['email' => $email])
            ->willReturn(null);

        $this->tokenServiceMock
            ->expects($this->never())
            ->method('createToken');

        $this->emailServiceMock
            ->expects($this->never())
            ->method('sendWelcomeEmail');

        $result = $this->userService->resendActivation($email);

        $this->assertNull($result);
    }

    public function testResendActivationReturnsNullWhenUserAlreadyActivated(): void
    {
        $email = "active@example.com";

        $userMock = $this->createMock(User::class);
        $userMock->expects($this->once())
            ->method('isActivated')
            ->willReturn(true);

        $this->userRepositoryMock
            ->expects($this->once())
            ->method('findOneBy')
            ->with(['email' => $email])
            ->willReturn($userMock);

        $this->tokenServiceMock
            ->expects($this->never())
            ->method('createToken');

        $this->emailServiceMock
            ->expects($this->never())
            ->method('sendWelcomeEmail');

        $result = $this->userService->resendActivation($email);

        $this->assertNull($result);
    }

}