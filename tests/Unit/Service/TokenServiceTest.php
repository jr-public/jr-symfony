<?php

namespace App\Tests\Unit\Service;

use App\Entity\Token;
use App\Entity\User;
use App\Enum\TokenType;
use App\Exception\AuthException;
use App\Repository\TokenRepository;
use PHPUnit\Framework\TestCase;
use App\Service\TokenService;
use Doctrine\ORM\EntityManagerInterface;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use PHPUnit\Framework\MockObject\MockObject;

class TokenServiceTest extends TestCase
{
	protected string $secret;
	protected string $algorithm;
	protected TokenService $service;
	protected EntityManagerInterface&MockObject $em;
    protected TokenRepository&MockObject $tokenRepo;

	protected function setUp(): void
	{
		$this->secret = 'test-secret';
		$this->algorithm = 'HS256';
		$this->em = $this->createMock(EntityManagerInterface::class);
        $this->tokenRepo = $this->createMock(TokenRepository::class);

		$this->service = new TokenService(
			$this->em,
            $this->tokenRepo,
			$this->secret,
			$this->algorithm
		);
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
	 * createSessionJwt() testing methods
	 */
	public function testCreateSessionJwtEncodesCorrectPayload(): void
	{
		$identifier = 'user123';

		$token = $this->service->createSessionJwt($identifier);

		$decoded = JWT::decode($token, new Key($this->secret, $this->algorithm));

		$this->assertEquals('session', $decoded->type);
		$this->assertEquals($identifier, $decoded->sub);
		$this->assertIsInt($decoded->iat);
		$this->assertIsInt($decoded->exp);
		$this->assertGreaterThan($decoded->iat, $decoded->exp);
	}
	/**
	 * decodeSessionJwt() testing methods
	 */
    public function testDecodeSessionJwtThrowsOnBeforeValid(): void
    {
		$identifier = 'user123';
		$token = $this->createTestJwt($identifier);

		$decoded = $this->service->decodeSessionJwt($token);

		$this->assertEquals('session', $decoded->type);
		$this->assertEquals($identifier, $decoded->sub);
		$this->assertIsInt($decoded->iat);
		$this->assertIsInt($decoded->exp);
		$this->assertGreaterThan($decoded->iat, $decoded->exp);
    }

    public function testDecodeSessionJwtThrowsOnExpired(): void
    {
		$identifier = 'user123';
		$token = $this->createTestJwt($identifier, -10);

		$this->expectException(AuthException::class);
		$this->expectExceptionMessage('TOKEN_EXPIRED');
		$this->service->decodeSessionJwt($token);
    }

    public function testDecodeSessionJwtThrowsOnSignatureInvalid(): void
    {
        $token = JWT::encode([], 'BadSecret', $this->algorithm);

		$this->expectException(AuthException::class);
		$this->expectExceptionMessage('TOKEN_SIGNATURE');
		$this->service->decodeSessionJwt($token);
    }

    public function testDecodeSessionJwtThrowsOnInvalidArgument(): void
    {
		$this->expectException(AuthException::class);
		$this->expectExceptionMessage('TOKEN_UNEXPECTED_VALUE');
		$this->service->decodeSessionJwt('');
    }


    public function testDecodeSessionJwtThrowsOnUnexpectedValue(): void
    {
		$this->expectException(AuthException::class);
		$this->expectExceptionMessage('TOKEN_DOMAIN');
		$this->service->decodeSessionJwt('aaa.bbb.ccc');
    }
	public function testDecodeSessionJwtWithMissingTypeClaimThrowsException(): void
	{
        $jwtPayload = [
            'exp' => new \DateTimeImmutable('+10 minutes')->getTimestamp(),
        ];
        $token = JWT::encode($jwtPayload, $this->secret, $this->algorithm);

		$this->expectExceptionMessage('TOKEN_TYPE_REQUIRED');
		$decoded = $this->service->decodeSessionJwt($token);
	}
	public function testDecodeSessionJwtWithMissingSubjectClaimThrowsException(): void
	{
        $jwtPayload = [
            'exp' => new \DateTimeImmutable('+10 minutes')->getTimestamp(),
			'type' => 'session',
        ];
        $token = JWT::encode($jwtPayload, $this->secret, $this->algorithm);

		$this->expectExceptionMessage('TOKEN_SUBJECT_REQUIRED');
		$decoded = $this->service->decodeSessionJwt($token);
	}
	public function testDecodeSessionJwtWithWrongTypeClaimThrowsException(): void
	{
        $jwtPayload = [
            'exp' => new \DateTimeImmutable('+10 minutes')->getTimestamp(),
			'type' => 'BadType',
        ];
        $token = JWT::encode($jwtPayload, $this->secret, $this->algorithm);

		$this->expectExceptionMessage('TOKEN_TYPE_MISMATCH');
		$decoded = $this->service->decodeSessionJwt($token);
	}

    public function testDecodeSessionJwtReturnsDecodedObject(): void
	{
        $jwtPayload = [
            'exp' => new \DateTimeImmutable('+10 minutes')->getTimestamp(),
			'type' => 'session',
			'sub' => 'test@email.com',
        ];
        $token = JWT::encode($jwtPayload, $this->secret, $this->algorithm);

		$decoded = $this->service->decodeSessionJwt($token);
		$this->assertIsObject($decoded);
		$this->assertObjectHasProperty('exp', $decoded);
		$this->assertObjectHasProperty('type', $decoded);
	}
    /**
     * random() testing methods
     */
    public function testRandomThrowsOnInvalidLength(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Length must be at least 1');
        
        $this->service->random(0);
    }

    public function testRandomGeneratesHexEncodingCorrectFormat(): void
    {
        $length = 16; // 16 bytes = 32 hex characters
        $result = $this->service->random($length, 'hex');

        // 1. Check Length: Hex encoding outputs 2 characters per byte
        $this->assertSame($length * 2, strlen($result));
        
        // 2. Check Format: Should contain only hexadecimal characters
        $this->assertMatchesRegularExpression('/^[0-9a-f]+$/', $result);
    }

    public function testRandomGeneratesBase64EncodingCorrectFormat(): void
    {
        $length = 18;
        $result = $this->service->random($length, 'base64');
        
        // 1. Check Format: Base64 can contain A-Z, a-z, 0-9, '+', '/', and '=' padding.
        $this->assertMatchesRegularExpression('/^[a-zA-Z0-9+\/]+=*$/', $result);
        
        // 2. Check that decoding the result returns the original number of bytes
        $this->assertSame($length, strlen(base64_decode($result)));
    }

    public function testRandomGeneratesUrlSafeEncodingCorrectFormat(): void
    {
        $length = 18;
        $result = $this->service->random($length, 'urlsafe');
        
        // 1. Check Format: URL-safe replaces '+' with '-' and '/' with '_', and trims '=' padding.
        $this->assertDoesNotMatchRegularExpression('/[+\/=]/', $result, 'URL-safe encoding should not contain standard base64 characters or padding.');
        
        // 2. Check that decoding the result returns the original number of bytes
        // To check this, we must reverse the URL-safe encoding steps: add padding and replace characters.
        $base64 = strtr($result, '-_', '+/');
        // Add padding back for proper decoding if needed
        $paddedBase64 = str_pad($base64, strlen($base64) % 4, '=', STR_PAD_RIGHT); 
        
        $this->assertSame($length, strlen(base64_decode($paddedBase64)));
    }

    public function testRandomGeneratesRawEncodingCorrectFormat(): void
    {
        $length = 10;
        $result = $this->service->random($length, 'raw');

        // 1. Check Length: Should match the requested byte length exactly
        $this->assertSame($length, strlen($result));
        
        // 2. Check Type: Assert that it is a raw binary string
        $this->assertIsString($result);
    }

    public function testRandomThrowsOnInvalidEncoding(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid encoding: bad_value');
        
        $this->service->random(16, 'bad_value');
    }

	/**
	 * createToken() testing methods
	 */
    public function testCreateTokenReturnsValidTokenString(): void
    {
        /** @var User&MockObject $user */
        $user = $this->createMock(User::class);

        /** @var Token&MockObject $tokenEntity */
        $tokenEntity = $this->createMock(Token::class);
        $tokenEntity->method('getId')->willReturn('someId');

        /** @var TokenService&MockObject $service */
        $service = $this->getMockBuilder(TokenService::class)
            ->onlyMethods(['newTokenEntity', 'random'])
            ->setConstructorArgs([$this->em, $this->tokenRepo, $this->secret, $this->algorithm])
            ->getMock();

        $service->method('random')->willReturn('fixedRandomSecret');
        $service->method('newTokenEntity')->willReturn($tokenEntity);

        $result = $service->createToken(TokenType::ActivateAccount, $user);

        $this->assertSame(
            'someId.fixedRandomSecret',
            $result,
            'Token string should combine the token ID and generated secret correctly.'
        );
    }
    /**
     * newTokenEntity() testing methods
     */
    public function testNewTokenEntityCreatesAndPersistsToken(): void
    {
        $hash = 'testHash';
        $user = $this->createMock(User::class);
        $type = TokenType::ActivateAccount;
        $expiresAt = new \DateTimeImmutable('+10 minutes');

        $this->em->expects($this->once())
            ->method('persist')
            ->with($this->isInstanceOf(Token::class));
        $this->em->expects($this->once())
            ->method('flush');

        $token = $this->service->newTokenEntity($hash, $user, $type, $expiresAt);
        
        $this->assertInstanceOf(Token::class, $token);
        $this->assertSame($user, $token->getOwner(), 'The owner must be set correctly.');
        $this->assertSame($type, $token->getType(), 'The type must be set correctly.');
        $this->assertSame($expiresAt, $token->getExpiresAt(), 'The expiration time must be set correctly.');
        $this->assertSame($hash, $token->getHash(), 'The hash must be set correctly.');
    }
    /**
     * verifyToken() testing methods
     */
    public function testVerifyTokenReturnsUser(): void
    {
        $id = '12345';
        $secret = 'super_secret_value';
        $fullToken = $id . '.' . $secret;
        $type = TokenType::ActivateAccount;

        /** @var User&MockObject $expectedUser */
        $expectedUser = $this->createMock(User::class);
        /** @var Token&MockObject $tokenEntity */
        $tokenEntity = $this->createMock(Token::class);
        
        $tokenEntity->method('getHash')->willReturn(password_hash($secret, PASSWORD_BCRYPT));
        $tokenEntity->method('getOwner')->willReturn($expectedUser);
        
        $this->tokenRepo->expects($this->once())
            ->method('findValidToken')
            ->with($id, $type)
            ->willReturn($tokenEntity);

        // Assert the TokenService marks the entity as used
        $tokenEntity->expects($this->once())
            ->method('setUsed');
            
        // Assert the TokenService delegates the saving/flushing to the repository
        $this->tokenRepo->expects($this->once())
            ->method('save')
            ->with($tokenEntity); 

        $actualUser = $this->service->verifyToken($fullToken, $type);

        $this->assertSame($expectedUser, $actualUser);
    }
    
    public function testVerifyTokenThrowsOnInvalidFormat(): void
    {
        $fullToken = 'badFormatToken';
        $type = TokenType::ActivateAccount;

        $this->expectException(AuthException::class);
        $this->expectExceptionMessage('TOKEN_INVALID_FORMAT');

        $this->service->verifyToken($fullToken, $type);
    }

    public function testVerifyTokenThrowsOnTokenNotFound(): void
    {
        $fullToken = '123.badToken';
        $type = TokenType::ActivateAccount;

        $this->tokenRepo->expects($this->once())
            ->method('findValidToken')
            ->willReturn(null);

        $this->expectException(AuthException::class);
        $this->expectExceptionMessage('TOKEN_NOT_FOUND');
        $this->expectExceptionCode(404);

        $this->service->verifyToken($fullToken, $type);
    }

    public function testVerifyTokenThrowsOnSecretMismatch(): void
    {
        $id = '12345';
        $secret = 'super_secret_value';
        $fullToken = $id . '.' . $secret;
        $type = TokenType::ActivateAccount;

        /** @var Token&MockObject $tokenEntity */
        $tokenEntity = $this->createMock(Token::class);
        
        $this->tokenRepo->expects($this->once())
            ->method('findValidToken')
            ->with($id, $type)
            ->willReturn($tokenEntity);

        $tokenEntity->method('getHash')->willReturn(password_hash('wrongSecret', PASSWORD_BCRYPT));

        $this->expectException(AuthException::class);
        $this->expectExceptionMessage('TOKEN_SECRET_MISMATCH');
        $this->expectExceptionCode(401);

        $this->service->verifyToken($fullToken, $type);
    }
}
