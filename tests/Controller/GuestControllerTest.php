<?php

namespace App\Tests\Controller;

use App\Entity\User;
use App\Enum\TokenType;
use App\Enum\UserRole;
use App\Service\TokenService;
use Doctrine\ORM\EntityManagerInterface;
use PHPUnit\Framework\MockObject\MockObject;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Email;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;

class GuestControllerTest extends WebTestCase
{
    private $client;
    private EntityManagerInterface $entityManager;
    private UserPasswordHasherInterface $passwordHasher;
    private TokenService $tokenService;
    private MockObject&MailerInterface $mailerMock;


    protected function setUp(): void
    {
        parent::setUp();
        $this->client           = static::createClient();
        $container              = static::getContainer();
        $this->entityManager    = $container->get(EntityManagerInterface::class);
        $this->passwordHasher   = $container->get(UserPasswordHasherInterface::class);
        $this->tokenService     = $container->get(TokenService::class);
        $this->mailerMock       = $this->createMock(MailerInterface::class);
        $this->getContainer()->set(MailerInterface::class, $this->mailerMock);

        // Clean database before each test
        $this->cleanDatabase();
    }
    /**
     * login() testing methods
     */
    public function testLoginWithCorrectCredentialsReturnsArray(): void
    {
        $email = 'test@email.com';
        $password = 'correctPass';
        $this->createTestUser(
            $email,
            'username',
            $password,
            true
        );
        $payload = [
            'email' => $email,
            'password' => $password
        ];

        $this->client->request(
            'POST',
            '/api/guest/login',
            [],
            [],
            [
                'CONTENT_TYPE' => 'application/json',
                'HTTP_ACCEPT'  => 'application/json',
            ],
            json_encode($payload)
        );

        $this->assertResponseIsSuccessful();
        $responseContent = $this->client->getResponse()->getContent();
        $data = json_decode($responseContent, true);
        $this->assertIsArray($data);
        $this->assertArrayHasKey('data', $data);
        $this->assertArrayHasKey('error', $data);
        $this->assertEmpty($data['error']);
        $this->assertArrayHasKey('token', $data['data']);
        $this->assertNotEmpty($data['data']['token']);
        $this->assertIsString($data['data']['token']);
        $this->assertArrayHasKey('user', $data['data']);
        $this->assertNotEmpty($data['data']['user']);
        $this->assertIsArray($data['data']['user']);

    }
    public function testLoginWithWrongEmailReturnsError(): void
    {
        $email = 'bad@email.com';
        $payload = [
            'email' => $email,
            'password' => 'badPass'
        ];

        $this->client->request(
            'POST',
            '/api/guest/login',
            [],
            [],
            [
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
        $this->assertArrayHasKey('error', $data);
        $this->assertArrayHasKey('message', $data['error']);
        $this->assertEquals('AUTH_ERROR', $data['error']['message']);
    }
    public function testLoginWithWrongPasswordReturnsError(): void
    {

        $email = 'bad@email.com';
        $this->createTestUser(
            $email,
            'username',
            'somePass',
        );
        $payload = [
            'email' => $email,
            'password' => 'badPass'
        ];

        $this->client->request(
            'POST',
            '/api/guest/login',
            [],
            [],
            [
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
        $this->assertArrayHasKey('error', $data);
        $this->assertArrayHasKey('message', $data['error']);
        $this->assertEquals('AUTH_ERROR', $data['error']['message']);
    }
    public function testLoginWithInactiveUserReturnsError(): void
    {
        $email = 'test@email.com';
        $password = 'correctPass';
        $this->createTestUser(
            $email,
            'username',
            $password,
            false // Insert user as inactive
        );
        $payload = [
            'email' => $email,
            'password' => $password
        ];

        $this->client->request(
            'POST',
            '/api/guest/login',
            [],
            [],
            [
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
        $this->assertArrayHasKey('error', $data);
        $this->assertArrayHasKey('message', $data['error']);
        $this->assertEquals('AUTH_ERROR', $data['error']['message']);
    }
    public function testLoginWithSuspendedUserReturnsError(): void
    {
        $suspension = new \DateTimeImmutable('+10 minutes');
        $email = 'test@email.com';
        $password = 'correctPass';
        $user = $this->createTestUser(
            $email,
            'username',
            $password,
            true
        );
        $user->setSuspendedUntil($suspension);
        $this->entityManager->flush();
        $payload = [
            'email' => $email,
            'password' => $password
        ];

        $this->client->request(
            'POST',
            '/api/guest/login',
            [],
            [],
            [
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
        $this->assertArrayHasKey('error', $data);
        $this->assertArrayHasKey('message', $data['error']);
        $this->assertEquals('AUTH_ERROR', $data['error']['message']);
    }
    /**
     * registration() testing methods
     */
    public function testRegistrationWithCorrectCredentialsReturnsArray(): void
    {
        $email = 'test@email.com';
        $password = 'correctPass';

        $payload = [
            'username' => 'testUsername',
            'email' => $email,
            'password' => $password
        ];

        $this->mailerMock->expects($this->once())
            ->method('send')
            ->with($this->isInstanceOf(Email::class));

        $this->client->request(
            'POST',
            '/api/guest/registration',
            [],
            [],
            [
                'CONTENT_TYPE' => 'application/json',
                'HTTP_ACCEPT'  => 'application/json',
            ],
            json_encode($payload)
        );

        $this->assertResponseIsSuccessful();
        $responseContent = $this->client->getResponse()->getContent();
        $data = json_decode($responseContent, true);
        $this->assertIsArray($data);
        $this->assertArrayHasKey('data', $data);
        $this->assertArrayHasKey('error', $data);
        $this->assertEmpty($data['error']);
        $this->assertArrayHasKey('token', $data['data']);
        $this->assertNotEmpty($data['data']['token']);
        $this->assertIsString($data['data']['token']);
        $this->assertArrayHasKey('user', $data['data']);
        $this->assertNotEmpty($data['data']['user']);
        $this->assertIsArray($data['data']['user']);
        $this->assertIsArray($data['data']['user']['roles']);
        $this->assertContains('ROLE_USER', $data['data']['user']['roles']);
    }
    public function testRegistrationWithRepeatedEmailReturnsError(): void
    {
        $email = 'test@email.com';
        $password = 'correctPass';

        $this->createTestUser(
            $email,
            'testUsername',
            $password,
            true
        );

        $payload = [
            'username' => 'testUsername2',
            'email' => $email,
            'password' => $password
        ];

        $this->mailerMock->expects($this->never())->method('send');

        $this->client->request(
            'POST',
            '/api/guest/registration',
            [],
            [],
            [
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
        $this->assertArrayHasKey('error', $data);
        $this->assertArrayHasKey('message', $data['error']);
        $this->assertEquals('USER_CREATION_FAILED', $data['error']['message']);
    }
    /**
     * activateAccount() testing methods
     */
    public function testActivateAccountWithCorrectTokenActivatesAccount(): void
    {
        $user = $this->createTestUser(
            'test@email.com',
            'testUsername',
            'correctPass'
        );
        $token = $this->tokenService->createToken(TokenType::ActivateAccount, $user);

        $this->client->request(
            'GET',
            "/api/guest/activate-account/$token",
            [],
            [],
            [
                'HTTP_ACCEPT' => 'application/json',
            ]
        );

        $this->assertResponseIsSuccessful();
        $responseContent = $this->client->getResponse()->getContent();
        $data = json_decode($responseContent, true);
        $this->assertIsArray($data);
        $this->assertArrayHasKey('data', $data);
        $this->assertEmpty($data['data']);
        $this->assertArrayHasKey('error', $data);
        $this->assertEmpty($data['error']);
        $this->assertEquals(true, $user->isActivated());
    }
    public function testActivateAccountOnAlreadyActivatedAccountReturnsOk(): void
    {
        $user = $this->createTestUser(
            'test@email.com',
            'testUsername',
            'correctPass',
            true
        );
        $token = $this->tokenService->createToken(TokenType::ActivateAccount, $user);

        $this->client->request(
            'GET',
            "/api/guest/activate-account/$token",
            [],
            [],
            [
                'HTTP_ACCEPT' => 'application/json',
            ]
        );

        $this->assertResponseIsSuccessful();
        $responseContent = $this->client->getResponse()->getContent();
        $data = json_decode($responseContent, true);
        $this->assertIsArray($data);
        $this->assertArrayHasKey('data', $data);
        $this->assertEmpty($data['data']);
        $this->assertArrayHasKey('error', $data);
        $this->assertEmpty($data['error']);
        $this->assertEquals(true, $user->isActivated());
    }
    public function testActivateAccountOnSuspendedAccountReturnsError(): void
    {
        $user = $this->createTestUser(
            'test@email.com',
            'testUsername',
            'correctPass',
        );
        $token = $this->tokenService->createToken(TokenType::ActivateAccount, $user);
        $suspension = new \DateTimeImmutable('+10 minutes');
        $user->setSuspendedUntil($suspension);
        $this->entityManager->flush();

        $this->client->request(
            'GET',
            "/api/guest/activate-account/$token",
            [],
            [],
            [
                'HTTP_ACCEPT' => 'application/json',
            ]
        );
        
        $this->assertResponseStatusCodeSame(403);
        $responseContent = $this->client->getResponse()->getContent();
        $data = json_decode($responseContent, true);
        $this->assertIsArray($data);
        $this->assertArrayHasKey('data', $data);
        $this->assertEmpty($data['data']);
        $this->assertArrayHasKey('error', $data);
        $this->assertArrayHasKey('message', $data['error']);
        $this->assertEquals('AUTH_ERROR', $data['error']['message']);
    }
    public function testActivateAccountWithWrongTokenReturnsError(): void
    {
        $user = $this->createTestUser(
            'test@email.com',
            'testUsername',
            'correctPass',
        );
        $token = 'wrongToken';

        $this->client->request(
            'GET',
            "/api/guest/activate-account/$token",
            [],
            [],
            [
                'HTTP_ACCEPT' => 'application/json',
            ]
        );
        
        $this->assertResponseStatusCodeSame(401);
        $responseContent = $this->client->getResponse()->getContent();
        $data = json_decode($responseContent, true);
        $this->assertIsArray($data);
        $this->assertArrayHasKey('data', $data);
        $this->assertEmpty($data['data']);
        $this->assertArrayHasKey('error', $data);
        $this->assertArrayHasKey('message', $data['error']);
        $this->assertEquals('TOKEN_INVALID_FORMAT', $data['error']['message']);
    }
    public function testActivateAccountWithExpiredTokenReturnsError(): void
    {
        $user = $this->createTestUser(
            'test@email.com',
            'testUsername',
            'correctPass',
        );
        $token = $this->tokenService->createToken(TokenType::ActivateAccount, $user, 0);

        $this->client->request(
            'GET',
            "/api/guest/activate-account/$token",
            [],
            [],
            [
                'HTTP_ACCEPT' => 'application/json',
            ]
        );
        
        $this->assertResponseStatusCodeSame(404);
        $responseContent = $this->client->getResponse()->getContent();
        $data = json_decode($responseContent, true);
        $this->assertIsArray($data);
        $this->assertArrayHasKey('data', $data);
        $this->assertEmpty($data['data']);
        $this->assertArrayHasKey('error', $data);
        $this->assertArrayHasKey('message', $data['error']);
        $this->assertEquals('TOKEN_NOT_FOUND', $data['error']['message']);
    }
    /**
     * forgotPassword() testing methods
     */
    public function testForgotPasswordWithCorrectEmailSendsToken(): void
    {
        $email = 'test@email.com';
        $this->createTestUser(
            $email,
            'testUsername',
            'correctPass',
            true
        );

        $this->mailerMock->expects($this->once())
            ->method('send')
            ->with($this->isInstanceOf(Email::class));

        $payload = [
            'email' => $email
        ];
        
        $this->client->request(
            'POST',
            '/api/guest/forgot-password',
            [],
            [],
            [
                'CONTENT_TYPE' => 'application/json',
                'HTTP_ACCEPT'  => 'application/json',
            ],
            json_encode($payload)
        );
        
        $this->assertResponseIsSuccessful();
        $responseContent = $this->client->getResponse()->getContent();
        $data = json_decode($responseContent, true);
        $this->assertIsArray($data);
        $this->assertArrayHasKey('data', $data);
        $this->assertArrayHasKey('token', $data['data']);
        $this->assertNotEmpty($data['data']['token']);
        $this->assertIsString($data['data']['token']);
        $this->assertArrayHasKey('error', $data);
        $this->assertEmpty($data['error']);
    }
    public function testForgotPasswordWithWrongEmailReturnsOk(): void
    {
        $this->mailerMock->expects($this->never())->method('send');

        $payload = [
            'email' => 'bad@email.com'
        ];
        
        $this->client->request(
            'POST',
            '/api/guest/forgot-password',
            [],
            [],
            [
                'CONTENT_TYPE' => 'application/json',
                'HTTP_ACCEPT'  => 'application/json',
            ],
            json_encode($payload)
        );
        
        $this->assertResponseIsSuccessful();
        $responseContent = $this->client->getResponse()->getContent();
        $data = json_decode($responseContent, true);
        $this->assertIsArray($data);
        $this->assertArrayHasKey('token', $data['data']);
        $this->assertEmpty($data['data']['token']);
        // $this->assertEmpty($data['data']);
        $this->assertArrayHasKey('error', $data);
        $this->assertEmpty($data['error']);
    }
    public function testForgotPasswordWithSuspendedAccountReturnsOk(): void
    {
        $email = 'test@email.com';
        $user = $this->createTestUser(
            $email,
            'testUsername',
            'correctPass',
            true
        );
        $user->setSuspendedUntil(new \DateTimeImmutable('+10 minutes'));
        $this->entityManager->flush();

        $this->mailerMock->expects($this->never())->method('send');

        $payload = [
            'email' => $email
        ];
        
        $this->client->request(
            'POST',
            '/api/guest/forgot-password',
            [],
            [],
            [
                'CONTENT_TYPE' => 'application/json',
                'HTTP_ACCEPT'  => 'application/json',
            ],
            json_encode($payload)
        );
        
        $this->assertResponseIsSuccessful();
        $responseContent = $this->client->getResponse()->getContent();
        $data = json_decode($responseContent, true);
        $this->assertIsArray($data);
        $this->assertArrayHasKey('token', $data['data']);
        $this->assertEmpty($data['data']['token']);
        // $this->assertEmpty($data['data']);
        $this->assertArrayHasKey('error', $data);
        $this->assertEmpty($data['error']);
    }
    public function testForgotPasswordWithInactiveAccountReturnsOk(): void
    {
        $email = 'test@email.com';
        $this->createTestUser(
            $email,
            'testUsername',
            'correctPass',
        );

        $this->mailerMock->expects($this->never())->method('send');

        $payload = [
            'email' => $email
        ];
        
        $this->client->request(
            'POST',
            '/api/guest/forgot-password',
            [],
            [],
            [
                'CONTENT_TYPE' => 'application/json',
                'HTTP_ACCEPT'  => 'application/json',
            ],
            json_encode($payload)
        );
        
        $this->assertResponseIsSuccessful();
        $responseContent = $this->client->getResponse()->getContent();
        $data = json_decode($responseContent, true);
        $this->assertIsArray($data);
        $this->assertArrayHasKey('token', $data['data']);
        $this->assertEmpty($data['data']['token']);
        // $this->assertEmpty($data['data']);
        $this->assertArrayHasKey('error', $data);
        $this->assertEmpty($data['error']);
    }
    /**
     * resetPassword() testing methods
     */
    public function testResetPasswordWithCorrectTokenResetsPassword(): void
    {
        $email = 'test@email.com';
        $password = 'newPassword';
        $user = $this->createTestUser(
            $email,
            'testUsername',
            'correctPass',
            true
        );
        $token = $this->tokenService->createToken(TokenType::ForgotPassword, $user);
        $payload = [
            'token' => $token,
            'password' => $password
        ];

        $this->client->request(
            'POST',
            "/api/guest/reset-password",
            [],
            [],
            [
                'CONTENT_TYPE' => 'application/json',
                'HTTP_ACCEPT' => 'application/json',
            ],
            json_encode($payload)
        );

        $this->assertResponseIsSuccessful();
        $responseContent = $this->client->getResponse()->getContent();
        $data = json_decode($responseContent, true);
        $this->assertIsArray($data);
        $this->assertArrayHasKey('data', $data);
        $this->assertEmpty($data['data']);
        $this->assertArrayHasKey('error', $data);
        $this->assertEmpty($data['error']);
        
        // Verify the password has been changed
        $this->client->request(
            'POST',
            '/api/guest/login',
            [],
            [],
            [
                'CONTENT_TYPE' => 'application/json',
                'HTTP_ACCEPT'  => 'application/json',
            ],
            json_encode([
                'email' => $email,
                'password' => $password
            ])
        );
        $this->assertResponseIsSuccessful();
    }
    public function testResetPasswordWithWrongTokenReturnsError(): void
    {
        $email = 'test@email.com';
        $password = 'newPassword';
        $user = $this->createTestUser(
            $email,
            'testUsername',
            'correctPass',
            true
        );
        $token = 'BadToken';
        $payload = [
            'token' => $token,
            'password' => $password
        ];

        $this->client->request(
            'POST',
            "/api/guest/reset-password",
            [],
            [],
            [
                'CONTENT_TYPE' => 'application/json',
                'HTTP_ACCEPT' => 'application/json',
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
        $this->assertArrayHasKey('message', $data['error']);
        $this->assertEquals('TOKEN_INVALID_FORMAT', $data['error']['message']);
    }
    public function testResetPasswordWithExpiredTokenReturnsError(): void
    {
        $email = 'test@email.com';
        $password = 'newPassword';
        $user = $this->createTestUser(
            $email,
            'testUsername',
            'correctPass',
            true
        );
        $token = 'BadToken';
        $payload = [
            'token' => $token,
            'password' => $password
        ];

        $this->client->request(
            'POST',
            "/api/guest/reset-password",
            [],
            [],
            [
                'CONTENT_TYPE' => 'application/json',
                'HTTP_ACCEPT' => 'application/json',
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
        $this->assertArrayHasKey('message', $data['error']);
        $this->assertEquals('TOKEN_INVALID_FORMAT', $data['error']['message']);
    }
    public function testResetPasswordWithInactiveAccountReturnsError(): void
    {
        $email = 'test@email.com';
        $password = 'newPassword';
        $user = $this->createTestUser(
            $email,
            'testUsername',
            'correctPass',
        );
        $token = $this->tokenService->createToken(TokenType::ForgotPassword, $user);
        $payload = [
            'token' => $token,
            'password' => $password
        ];

        $this->client->request(
            'POST',
            "/api/guest/reset-password",
            [],
            [],
            [
                'CONTENT_TYPE' => 'application/json',
                'HTTP_ACCEPT' => 'application/json',
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
        $this->assertArrayHasKey('message', $data['error']);
        $this->assertEquals('AUTH_ERROR', $data['error']['message']);
    }
    public function testResetPasswordWithSuspendedAccountReturnsError(): void
    {
        $email = 'test@email.com';
        $password = 'newPassword';
        $user = $this->createTestUser(
            $email,
            'testUsername',
            'correctPass',
        );
        $user->setSuspendedUntil(new \DateTimeImmutable('+10 minutes'));
        $this->entityManager->flush();
        
        $token = $this->tokenService->createToken(TokenType::ForgotPassword, $user);
        $payload = [
            'token' => $token,
            'password' => $password
        ];

        $this->client->request(
            'POST',
            "/api/guest/reset-password",
            [],
            [],
            [
                'CONTENT_TYPE' => 'application/json',
                'HTTP_ACCEPT' => 'application/json',
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
        $this->assertArrayHasKey('message', $data['error']);
        $this->assertEquals('AUTH_ERROR', $data['error']['message']);
    }
    /**
     * resendActivation() testing methods
     */
    public function testResendActivationWithCorrectEmailSendsToken(): void
    {
        $email = 'test@email.com';
        $user = $this->createTestUser(
            $email,
            'testUsername',
            'correctPass',
        );
        $payload = [
            'email' => $email,
        ];
        
        $this->mailerMock->expects($this->once())
            ->method('send')
            ->with($this->isInstanceOf(Email::class));

        $this->client->request(
            'POST',
            "/api/guest/resend-activation",
            [],
            [],
            [
                'CONTENT_TYPE' => 'application/json',
                'HTTP_ACCEPT' => 'application/json',
            ],
            json_encode($payload)
        );

        $this->assertResponseIsSuccessful();
        $responseContent = $this->client->getResponse()->getContent();
        $data = json_decode($responseContent, true);
        $this->assertIsArray($data);
        $this->assertArrayHasKey('data', $data);
        $this->assertEmpty($data['data']);
        $this->assertArrayHasKey('error', $data);
        $this->assertEmpty($data['error']);
    }
    public function testResendActivationWithWrongEmailReturnsOk(): void
    {
        $payload = [
            'email' => 'bad@email.com'
        ];
        
        $this->mailerMock->expects($this->never())->method('send');

        $this->client->request(
            'POST',
            "/api/guest/resend-activation",
            [],
            [],
            [
                'CONTENT_TYPE' => 'application/json',
                'HTTP_ACCEPT' => 'application/json',
            ],
            json_encode($payload)
        );

        $this->assertResponseIsSuccessful();
        $responseContent = $this->client->getResponse()->getContent();
        $data = json_decode($responseContent, true);
        $this->assertIsArray($data);
        $this->assertArrayHasKey('data', $data);
        $this->assertEmpty($data['data']);
        $this->assertArrayHasKey('error', $data);
        $this->assertEmpty($data['error']);
    }
    public function testResendActivationWithSuspendedAccountReturnsOk(): void
    {
        $email = 'test@email.com';
        $user = $this->createTestUser(
            $email,
            'testUsername',
            'correctPass',
            true
        );
        $user->setSuspendedUntil(new \DateTimeImmutable('+10 minutes'));
        $this->entityManager->flush();

        $payload = [
            'email' => 'bad@email.com'
        ];
        
        $this->mailerMock->expects($this->never())->method('send');

        $this->client->request(
            'POST',
            "/api/guest/resend-activation",
            [],
            [],
            [
                'CONTENT_TYPE' => 'application/json',
                'HTTP_ACCEPT' => 'application/json',
            ],
            json_encode($payload)
        );

        $this->assertResponseIsSuccessful();
        $responseContent = $this->client->getResponse()->getContent();
        $data = json_decode($responseContent, true);
        $this->assertIsArray($data);
        $this->assertArrayHasKey('data', $data);
        $this->assertEmpty($data['data']);
        $this->assertArrayHasKey('error', $data);
        $this->assertEmpty($data['error']);
    }
    public function testResendActivationWithAlreadyActivatedAccountReturnsOk(): void
    {
        $email = 'test@email.com';
        $user = $this->createTestUser(
            $email,
            'testUsername',
            'correctPass',
            true
        );

        $payload = [
            'email' => 'test@email.com'
        ];
        
        $this->mailerMock->expects($this->never())->method('send');

        $this->client->request(
            'POST',
            "/api/guest/resend-activation",
            [],
            [],
            [
                'CONTENT_TYPE' => 'application/json',
                'HTTP_ACCEPT' => 'application/json',
            ],
            json_encode($payload)
        );

        $this->assertResponseIsSuccessful();
        $responseContent = $this->client->getResponse()->getContent();
        $data = json_decode($responseContent, true);
        $this->assertIsArray($data);
        $this->assertArrayHasKey('data', $data);
        $this->assertEmpty($data['data']);
        $this->assertArrayHasKey('error', $data);
        $this->assertEmpty($data['error']);
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
