<?php

namespace App\Repository;

use App\Entity\Token;
use App\Enum\TokenType;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;

/**
 * @extends ServiceEntityRepository<Token>
 */
class TokenRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, Token::class);
    }

    public function findValidToken(string $id, TokenType $type): ?Token
    {
        return $this->createQueryBuilder('t')
            ->where('t.id = :id')
            ->andWhere('t.type = :type')
            ->andWhere('t.expires_at > :now')
            ->andWhere('t.used = false')
            ->setMaxResults(1)
            ->setParameter('id', $id)
            ->setParameter('type', $type)
            ->setParameter('now', new \DateTimeImmutable())
            ->getQuery()
            ->getOneOrNullResult();
    }
    public function save(Token $token): void
    {
        $em = $this->getEntityManager();
        $em->persist($token);
        $em->flush();
    }
}
