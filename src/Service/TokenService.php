<?php
namespace App\Service;

use App\Entity\Token;
use App\Entity\User;
use App\Enum\TokenType;
use Doctrine\ORM\EntityManagerInterface;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

use App\Exception\AuthException;
use App\Repository\TokenRepository;
use Firebase\JWT\BeforeValidException;
use Firebase\JWT\DomainException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\SignatureInvalidException;
use Symfony\Component\DependencyInjection\Attribute\Autowire;

class TokenService
{
    public function __construct(
        private readonly EntityManagerInterface $entityManager,
        private readonly TokenRepository $tokenRepo,
        #[Autowire('%app.token.secret%')] private readonly string $secret,
        #[Autowire('%app.token.algorithm.default%')] private readonly string $algorithm
    ) {}
    
    public function createSessionJwt(string $identifier, int $expirationMinutes = 60): string
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
    public function decodeSessionJwt(string $token): object
    {
        try {
            $decoded = JWT::decode($token, new Key($this->secret, $this->algorithm));
        }
        catch (BeforeValidException $e) {
            throw new AuthException($e->getMessage(), 'TOKEN_INVALID');
        }
        catch (ExpiredException $e) {
            throw new AuthException('TOKEN_EXPIRED', 'TOKEN_INVALID');
        }
        catch (SignatureInvalidException $e) {
            throw new AuthException('TOKEN_SIGNATURE', 'TOKEN_INVALID');
        }
        catch (\InvalidArgumentException $e) {
            throw new AuthException('TOKEN_INVALID_ARGUMENT', 'TOKEN_INVALID');
        }
        catch (\DomainException $e) {
            throw new AuthException('TOKEN_DOMAIN', 'TOKEN_INVALID');
        }
        catch (\UnexpectedValueException $e) {
            throw new AuthException('TOKEN_UNEXPECTED_VALUE', 'TOKEN_INVALID');
        }
        if (!isset($decoded->type)) {
            throw new AuthException('TOKEN_TYPE_REQUIRED', 'TOKEN_INVALID');
        }
        if ($decoded->type != 'session') {
            throw new AuthException('TOKEN_TYPE_MISMATCH', 'TOKEN_INVALID');
        }
        if (!isset($decoded->sub)) {
            throw new AuthException('TOKEN_SUBJECT_REQUIRED', 'TOKEN_INVALID');
        }
        return $decoded;
    }
    public function createToken(TokenType $type, User $user, int $expirationMinutes = 30): string
    {
        $secret     = $this->random(32, 'urlsafe');

        $token      = $this->newTokenEntity(
            user: $user,
            type: $type,
            hash: password_hash($secret, PASSWORD_BCRYPT),
            expiresAt: new \DateTimeImmutable("+$expirationMinutes minutes")
        );

        return $token->getId() . '.' . $secret;
    }

    public function newTokenEntity(string $hash, User $user, TokenType $type, \DateTimeImmutable $expiresAt): Token
    {
        $token = new Token($hash);
        $token->setOwner($user);
        $token->setType($type);
        $token->setExpiresAt($expiresAt);

        $this->entityManager->persist($token);
        $this->entityManager->flush();

        return $token;
    }

    public function verifyToken(string $fullToken, TokenType $type): User
    {
        // Split "id.secret"
        if (strpos($fullToken, '.') === false) {
            throw new AuthException('TOKEN_INVALID_FORMAT', 'TOKEN_INVALID');
        }
        [$id, $secret] = explode('.', $fullToken, 2);
        
        $tokenEntity = $this->tokenRepo->findValidToken($id, $type);
        if (!$tokenEntity) {
            throw new AuthException('TOKEN_NOT_FOUND', 'TOKEN_INVALID', 404);
        }
        if (!password_verify($secret, $tokenEntity->getHash())) {
            throw new AuthException('TOKEN_SECRET_MISMATCH', 'TOKEN_INVALID', 401);
        }
        
        // Mark as used
        $tokenEntity->setUsed();
        $this->tokenRepo->save($tokenEntity);

        return $tokenEntity->getOwner();
    }
    /**
     * Generate cryptographically secure random data
     * 
     * @param int $length Number of random bytes to generate
     * @param string $encoding Output encoding: 'hex', 'base64', 'urlsafe', or 'raw'
     * @return string
     * @throws \Exception if random_bytes fails
     */
    public function random(int $length = 32, string $encoding = 'urlsafe'): string
    {
        if ($length < 1) {
            throw new \InvalidArgumentException('Length must be at least 1');
        }

        $bytes = random_bytes($length);
        
        return match($encoding) {
            'hex'     => bin2hex($bytes),
            'base64'  => base64_encode($bytes),
            'urlsafe' => rtrim(strtr(base64_encode($bytes), '+/', '-_'), '='),
            'raw'     => $bytes,
            default   => throw new \InvalidArgumentException("Invalid encoding: $encoding")
        };
    }
}
