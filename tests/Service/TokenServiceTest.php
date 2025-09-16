<?php
namespace Tests\Service;

use App\Entity\User;
use App\Enum\UserRole;
use App\Repository\TokenRepository;
use App\Service\TokenService;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\EntityManagerInterface;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;

final class TokenServiceTest extends KernelTestCase
{

	private EntityManager $entityManager;
    private UserPasswordHasherInterface $passwordHasher;
	private TokenRepository $tokenRepository;
	private TokenService $tokenService;
    private string $secret = 'testing_key';
    private string $algorithm = 'HS256';

	protected function setUp(): void
    {
        parent::setUp();
        
        self::bootKernel();
        $container = static::getContainer();
        
        $this->entityManager    = $container->get(EntityManagerInterface::class);
        $this->passwordHasher   = $container->get(UserPasswordHasherInterface::class);
		$this->tokenRepository  = $container->get(TokenRepository::class);
        $this->tokenService 	= new TokenService(
			$this->entityManager,
			$this->tokenRepository,
			$this->secret,
			$this->algorithm
        );
        
        // Clean database before each test
        $this->cleanDatabase();
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

	/**
	 * createSessionJwt() testing methods
	 */
    public function testCreateSessionJwtReturnsValidToken(): void
	{
		$user = $this->createTestUser(
            'test@email.com',
            'testUsername',
            'correctPass',
            true
        );

        $token = $this->tokenService->createSessionJwt($user->getEmail());
		$this->assertNotEmpty($token);
		$this->assertIsString($token);

		$decoded = JWT::decode($token, new Key($this->secret, $this->algorithm));
		$this->assertIsObject($decoded);
		$this->assertObjectHasProperty('type', $decoded);
		$this->assertEquals('session', $decoded->type);
		$this->assertObjectHasProperty('sub', $decoded);
		$this->assertEquals($user->getEmail(), $decoded->sub);
	}
    public function testCreateSessionJwtReturnsValidTokenForCorrectUser(): void
	{
		$user = $this->createTestUser(
            'test@email.com',
            'testUsername',
            'correctPass',
            true
        );

        $token = $this->tokenService->createSessionJwt($user->getEmail());
		$this->assertNotEmpty($token);
		$this->assertIsString($token);

		$decoded = JWT::decode($token, new Key($this->secret, $this->algorithm));
		$this->assertIsObject($decoded);
		$this->assertObjectHasProperty('sub', $decoded);
		$this->assertEquals($user->getEmail(), $decoded->sub);
	}
    public function testCreateSessionJwtWithCustomExpirationReturnsValidToken(): void
	{
		$user = $this->createTestUser(
            'test@email.com',
            'testUsername',
            'correctPass',
            true
        );

        $token = $this->tokenService->createSessionJwt($user->getEmail(), 10);
		$this->assertNotEmpty($token);
		$this->assertIsString($token);

		$decoded = JWT::decode($token, new Key($this->secret, $this->algorithm));
		$this->assertIsObject($decoded);

		$expectedExpiration = new \DateTimeImmutable('+10 minutes')->getTimestamp();
		$variance = 2; 
		$this->assertGreaterThanOrEqual(
			$expectedExpiration - $variance,
			$decoded->exp,
			'Expiry is sooner than expected.'
		);
		$this->assertLessThanOrEqual(
			$expectedExpiration + $variance,
			$decoded->exp,
			'Expity is longer than expected.'
		);
	}

	/**
	 * decodeSessionJwt() testing methods
	 */
    public function testDecodeSessionJwtReturnsObject(): void
	{
        $jwtPayload = [
            'exp' => new \DateTimeImmutable('+10 minutes')->getTimestamp(),
			'type' => 'session',
			'sub' => 'test@email.com',
        ];
        $token = JWT::encode($jwtPayload, $this->secret, $this->algorithm);

		$decoded = $this->tokenService->decodeSessionJwt($token);
		$this->assertIsObject($decoded);
		$this->assertObjectHasProperty('exp', $decoded);
		$this->assertObjectHasProperty('type', $decoded);
	}
    public function testDecodeSessionJwtWithExpiredTokenThrowsException(): void
	{
        $jwtPayload = [
            'exp' => new \DateTimeImmutable('-10 minutes')->getTimestamp(),
        ];
        $token = JWT::encode($jwtPayload, $this->secret, $this->algorithm);

		$this->expectExceptionMessage('TOKEN_EXPIRED');
		$decoded = $this->tokenService->decodeSessionJwt($token);
	}
	public function testDecodeSessionJwtWithInvalidTokenFormatThrowsException(): void
	{
        $token = 'BadToken';

		$this->expectExceptionMessage('TOKEN_UNEXPECTED_VALUE');
		$decoded = $this->tokenService->decodeSessionJwt($token);
	}
	public function testDecodeSessionJwtWithMissingTypeClaimThrowsException(): void
	{
        $jwtPayload = [
            'exp' => new \DateTimeImmutable('+10 minutes')->getTimestamp(),
        ];
        $token = JWT::encode($jwtPayload, $this->secret, $this->algorithm);

		$this->expectExceptionMessage('TOKEN_TYPE_REQUIRED');
		$decoded = $this->tokenService->decodeSessionJwt($token);
	}
	public function testDecodeSessionJwtWithMissingSubjectClaimThrowsException(): void
	{
        $jwtPayload = [
            'exp' => new \DateTimeImmutable('+10 minutes')->getTimestamp(),
			'type' => 'session',
        ];
        $token = JWT::encode($jwtPayload, $this->secret, $this->algorithm);

		$this->expectExceptionMessage('TOKEN_SUBJECT_REQUIRED');
		$decoded = $this->tokenService->decodeSessionJwt($token);
	}
	public function testDecodeSessionJwtWithWrongTypeClaimThrowsException(): void
	{
        $jwtPayload = [
            'exp' => new \DateTimeImmutable('+10 minutes')->getTimestamp(),
			'type' => 'BadType',
        ];
        $token = JWT::encode($jwtPayload, $this->secret, $this->algorithm);

		$this->expectExceptionMessage('TOKEN_TYPE_MISMATCH');
		$decoded = $this->tokenService->decodeSessionJwt($token);
	}
	public function testDecodeSessionJwtWithInvalidSignatureThrowsException(): void
	{
        $jwtPayload = [];
        $token = JWT::encode($jwtPayload, 'BadSecret', $this->algorithm);

		$this->expectExceptionMessage('TOKEN_SIGNATURE');
		$decoded = $this->tokenService->decodeSessionJwt($token);
	}


	/**
	 * createToken() testing methods
	 */
    // public function testCreateTokenReturnsToken(): void
	// {}
    // public function testCreateTokenWithSpecificTypeReturnsValidToken(): void
	// {}
    // public function testCreateTokenWithCustomExpirationReturnsValidToken(): void
	// {}

	/**
	 * verifyToken() testing methods
	 */
	// public function testVerifyTokenWithValidTokenReturnsUser(): void
	// {}
	// public function testVerifyTokenWithInvalidTypeThrowsException(): void
	// {}
	// public function testVerifyTokenWithInvalidTokenFormatThrowsException(): void
	// {}
	// public function testVerifyTokenWithExpiredTokenThrowsException(): void
	// {}
	// public function testVerifyTokenWithMissingTokenThrowsException(): void
	// public function testVerifyTokenWithUsedTokenThrowsException(): void
	// public function testVerifyTokenWithInvalidSecretThrowsException(): void

	/**
	 * random() testing methods
	 */
    // public function testRandomReturnsCorrectLengthForRaw(): void
    // public function testRandomReturnsCorrectLengthForHex(): void
    // public function testRandomReturnsStringWithValidUrlsafeCharacters(): void
    // public function testRandomThrowsOnInvalidLength(): void
    // public function testRandomThrowsOnInvalidEncoding(): void
}
