<?php
namespace App\Service;

use App\Entity\Token;
use App\Entity\User;
use App\Enum\TokenType;
use Doctrine\ORM\EntityManagerInterface;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

use App\Exception\AuthException;
use Firebase\JWT\BeforeValidException;
use Firebase\JWT\DomainException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\SignatureInvalidException;
use Symfony\Component\DependencyInjection\Attribute\Autowire;

class TokenService
{
    public function __construct(
        private readonly EntityManagerInterface $entityManager,
        #[Autowire(env: 'APP_SECRET')] private readonly string $secret,
        #[Autowire('%app.algorithm.default%')] private readonly string $algorithm
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
            throw new AuthException('TOKEN_INVALID', $e->getMessage());
        }
        catch (ExpiredException $e) {
            throw new AuthException('TOKEN_INVALID', 'TOKEN_EXPIRED');
        }
        catch (SignatureInvalidException $e) {
            throw new AuthException('TOKEN_INVALID', 'TOKEN_SIGNATURE');
        }
        catch (\InvalidArgumentException $e) {
            throw new AuthException('TOKEN_INVALID', 'TOKEN_INVALID_ARGUMENT');
        }
        catch (\DomainException $e) {
            throw new AuthException('TOKEN_INVALID', 'TOKEN_DOMAIN');
        }
        catch (\UnexpectedValueException $e) {
            throw new AuthException('TOKEN_INVALID', 'TOKEN_UNEXPECTED_VALUE');
        }
        if (!isset($decoded->type)) {
            throw new AuthException('TOKEN_INVALID', 'TOKEN_TYPE_REQUIRED');
        }
        if ($decoded->type != 'session') {
            throw new AuthException('TOKEN_INVALID', 'TOKEN_TYPE_MISMATCH');
        }
        if (!isset($decoded->sub)) {
            throw new AuthException('TOKEN_INVALID', 'TOKEN_SUBJECT_REQUIRED');
        }
        return $decoded;
    }
    public function createToken(TokenType $type, User $user, int $expirationMinutes = 30): string
    {
        $now            = new \DateTimeImmutable();
        $expiration     = $now->modify("+$expirationMinutes minutes");
        
        $secret         = $this->random(32, 'urlsafe'); // 256-bit secret, URL-safe
        $hashedSecret   = password_hash($secret, PASSWORD_BCRYPT);
        $tokenEntity    = new Token($hashedSecret);
        $tokenEntity->setOwner($user);
        $tokenEntity->setType($type);
        $tokenEntity->setExpiresAt($expiration);
        $this->entityManager->persist($tokenEntity);
        $this->entityManager->flush();
        $token          = $tokenEntity->getId().'.'.$secret;
        return $token;
    }

    public function verifyToken(string $fullToken, TokenType $type): User
    {
        // Split "id.secret"
        if (strpos($fullToken, '.') === false) {
            throw new AuthException('TOKEN_INVALID', 'TOKEN_FORMAT');
        }
        [$id, $secret] = explode('.', $fullToken, 2);
        
        // Lookup by ID
        $qb = $this->entityManager->createQueryBuilder();
        $qb->select('t')
            ->from(Token::class, 't')
            ->where('t.id = :id')
            ->andWhere('t.type = :type')
            ->andWhere('t.expires_at > :now')
            ->andWhere('t.used = false')
            ->setMaxResults(1)
            ->setParameter('id', $id)
            ->setParameter('type', $type)
            ->setParameter('now', new \DateTimeImmutable());
        /** @var Token|null $tokenEntity */
        $tokenEntity = $qb->getQuery()->getOneOrNullResult();
        if (!$tokenEntity) {
            throw new AuthException('TOKEN_INVALID', 'TOKEN_NOT_FOUND');
        }

        // Verify secret
        if (!password_verify($secret, $tokenEntity->getHash())) {
            throw new AuthException('TOKEN_INVALID', 'TOKEN_SECRET_MISMATCH');
        }
        // Mark as used
        $tokenEntity->setUsed();
        $this->entityManager->flush();

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
