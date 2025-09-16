<?php

namespace App\Repository;

use App\Entity\User;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\ORM\QueryBuilder;
use Doctrine\Persistence\ManagerRegistry;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Core\User\PasswordUpgraderInterface;

/**
 * @extends ServiceEntityRepository<User>
 */
class UserRepository extends ServiceEntityRepository implements PasswordUpgraderInterface
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, User::class);
    }

    /**
     * Used to upgrade (rehash) the user's password automatically over time.
     */
    public function upgradePassword(PasswordAuthenticatedUserInterface $user, string $newHashedPassword): void
    {
        if (!$user instanceof User) {
            throw new UnsupportedUserException(sprintf('Instances of "%s" are not supported.', $user::class));
        }

        $user->setPassword($newHashedPassword);
        $this->getEntityManager()->persist($user);
        $this->getEntityManager()->flush();
    }

    //    /**
    //     * @return User[] Returns an array of User objects
    //     */
    //    public function findByExampleField($value): array
    //    {
    //        return $this->createQueryBuilder('u')
    //            ->andWhere('u.exampleField = :val')
    //            ->setParameter('val', $value)
    //            ->orderBy('u.id', 'ASC')
    //            ->setMaxResults(10)
    //            ->getQuery()
    //            ->getResult()
    //        ;
    //    }

    //    public function findOneBySomeField($value): ?User
    //    {
    //        return $this->createQueryBuilder('u')
    //            ->andWhere('u.exampleField = :val')
    //            ->setParameter('val', $value)
    //            ->getQuery()
    //            ->getOneOrNullResult()
    //        ;
    //    }

    public function findWithFilters(array $filters): array
    {
        $qb = $this->createQueryBuilder('u');
        
        $this->applyFilters($qb, $filters);
        $this->applySorting($qb, $filters);
        
        // Get total count before applying pagination
        $totalCount = $this->getTotalCount($qb);
        
        // Apply pagination
        $qb->setFirstResult($filters['offset'])
           ->setMaxResults($filters['limit']);
        
        $users = $qb->getQuery()->getArrayResult();
        
        return [
            'users' => $users,
            'totalCount' => $totalCount,
            'pagination' => $this->buildPaginationMetadata($totalCount, $filters['limit'], $filters['offset']),
        ];
    }

    private function applyFilters(QueryBuilder $qb, array $filters): void
    {
        if ($filters['search'] !== null) {
            $qb->andWhere('(u.username LIKE :search OR u.email LIKE :search)')
               ->setParameter('search', '%' . $filters['search'] . '%');
        }

        if ($filters['email'] !== null) {
            $qb->andWhere('u.email = :email')
               ->setParameter('email', $filters['email']);
        }

        if ($filters['role'] !== null) {
            $qb->andWhere('JSON_CONTAINS(u.roles, :role) = 1')
               ->setParameter('role', json_encode($filters['role']));
        }

        if ($filters['isActivated'] !== null) {
            $qb->andWhere('u.isActivated = :isActivated')
               ->setParameter('isActivated', $filters['isActivated']);
        }

        if ($filters['createdAfter'] !== null) {
            $qb->andWhere('u.created_at >= :createdAfter')
               ->setParameter('createdAfter', $filters['createdAfter']);
        }

        if ($filters['createdBefore'] !== null) {
            $qb->andWhere('u.created_at <= :createdBefore')
               ->setParameter('createdBefore', $filters['createdBefore']);
        }

        // Handle status filter if it maps to activation state
        if ($filters['status'] !== null) {
            match ($filters['status']) {
                'active' => $qb->andWhere('u.isActivated = true'),
                'pending' => $qb->andWhere('u.isActivated = false'),
                'suspended' => $qb->andWhere('u.isActivated = false'), // Adjust logic as needed
            };
        }
    }

    private function applySorting(QueryBuilder $qb, array $filters): void
    {
        $allowedSortFields = [
            'username' => 'u.username',
            'email' => 'u.email',
            'created_at' => 'u.created_at',
            'role' => 'u.roles', // Note: sorting by JSON field might need special handling
        ];

        $sortField = $allowedSortFields[$filters['sortBy']] ?? 'u.created_at';
        $sortOrder = strtoupper($filters['sortOrder']);

        $qb->orderBy($sortField, $sortOrder);
    }

    private function getTotalCount(QueryBuilder $qb): int
    {
        // Clone the query builder to avoid modifying the original
        $countQb = clone $qb;
        
        // Reset select, order by, and pagination for count query
        $countQb->select('COUNT(u.id)')
                ->resetDQLPart('orderBy')
                ->setFirstResult(null)
                ->setMaxResults(null);
        
        return (int) $countQb->getQuery()->getSingleScalarResult();
    }

    private function buildPaginationMetadata(int $totalCount, int $limit, int $offset): array
    {
        $currentPage = (int) floor($offset / $limit) + 1;
        $totalPages = (int) ceil($totalCount / $limit);
        
        return [
            'totalCount' => $totalCount,
            'limit' => $limit,
            'offset' => $offset,
            'currentPage' => $currentPage,
            'totalPages' => $totalPages,
            'hasNextPage' => ($offset + $limit) < $totalCount,
            'hasPreviousPage' => $offset > 0,
        ];
    }
}
