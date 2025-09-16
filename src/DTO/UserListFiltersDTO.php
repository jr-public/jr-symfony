<?php
namespace App\DTO;

use App\Enum\UserRole;
use Symfony\Component\Validator\Constraints as Assert;

final class UserListFiltersDTO
{
    #[Assert\Length(min: 2, max: 100)]
    #[Assert\Regex(
        pattern: '/^[a-zA-Z0-9\s\-_.@]+$/',
        message: 'Search term contains invalid characters'
    )]
    public readonly ?string $search;

    #[Assert\Choice(choices: ['active', 'pending', 'suspended'])]
    public readonly ?string $status;

    #[Assert\Choice(choices: [UserRole::Admin->value, UserRole::User->value])]
    public readonly ?string $role;

    #[Assert\Email]
    public readonly ?string $email;

    #[Assert\Type('bool')]
    public readonly ?bool $isActivated;

    #[Assert\DateTime]
    #[Assert\Type('\DateTimeInterface')]
    public readonly ?\DateTimeInterface $createdAfter;

    #[Assert\DateTime]
    #[Assert\Type('\DateTimeInterface')]
    public readonly ?\DateTimeInterface $createdBefore;

    #[Assert\Choice(choices: ['username', 'email', 'created_at', 'role'])]
    public readonly string $sortBy;

    #[Assert\Choice(choices: ['asc', 'desc'])]
    public readonly string $sortOrder;

    #[Assert\Positive]
    #[Assert\LessThanOrEqual(100)]
    public readonly int $limit;

    #[Assert\PositiveOrZero]
    public readonly int $offset;

    public function __construct(
        ?string $search = null,
        ?string $status = null,
        ?string $role = null,
        ?string $email = null,
        ?bool $isActivated = null,
        ?int $minAge = null,
        ?int $maxAge = null,
        ?\DateTimeInterface $createdAfter = null,
        ?\DateTimeInterface $createdBefore = null,
        ?\DateTimeInterface $lastLoginAfter = null,
        ?\DateTimeInterface $lastLoginBefore = null,
        string $sortBy = 'created_at',
        string $sortOrder = 'desc',
        int $limit = 20,
        int $offset = 0
    ) {
        $this->search = $search;
        $this->status = $status;
        $this->role = $role;
        $this->email = $email;
        $this->isActivated = $isActivated;
        $this->createdAfter = $createdAfter;
        $this->createdBefore = $createdBefore;
        $this->sortBy = $sortBy;
        $this->sortOrder = $sortOrder;
        $this->limit = $limit;
        $this->offset = $offset;
    }

    public function hasFilters(): bool
    {
        return $this->search !== null
            || $this->status !== null
            || $this->role !== null
            || $this->email !== null
            || $this->isActivated !== null
            || $this->createdAfter !== null
            || $this->createdBefore !== null;
    }

    public function toArray(): array
    {
        return [
            'search' => $this->search,
            'status' => $this->status,
            'role' => $this->role,
            'email' => $this->email,
            'isActivated' => $this->isActivated,
            'createdAfter' => $this->createdAfter?->format('Y-m-d H:i:s'),
            'createdBefore' => $this->createdBefore?->format('Y-m-d H:i:s'),
            'sortBy' => $this->sortBy,
            'sortOrder' => $this->sortOrder,
            'limit' => $this->limit,
            'offset' => $this->offset,
        ];
    }
}