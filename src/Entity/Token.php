<?php

namespace App\Entity;

use App\Enum\TokenType;
use App\Repository\TokenRepository;
use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Uid\Uuid;

#[ORM\Entity(repositoryClass: TokenRepository::class)]
#[ORM\Index(columns: ['owner_id'])]
#[ORM\Index(columns: ['expires_at'])]
class Token
{
    #[ORM\Id]
    #[ORM\Column(type: 'uuid', unique: true)]
    private Uuid $id;

    #[ORM\ManyToOne]
    #[ORM\JoinColumn(nullable: false, onDelete: 'CASCADE')]
    private User $owner;

    #[ORM\Column]
    private string $hash;

    #[ORM\Column(enumType: TokenType::class)]
    private TokenType $type;

    #[ORM\Column]
    private \DateTimeImmutable $expires_at;

    #[ORM\Column]
    private \DateTimeImmutable $created_at;

    #[ORM\Column]
    private bool $used = false;

    public function __construct(string $hash)
    {
        $this->id = Uuid::v4();
        $this->created_at = new \DateTimeImmutable();
        $this->hash = $hash;
    }
    public function toArray(): array {
        return get_object_vars($this);
    }

    public function getId(): string
    {
        return $this->id;
    }

    public function getOwner(): ?User
    {
        return $this->owner;
    }

    public function setOwner(?User $owner): static
    {
        $this->owner = $owner;

        return $this;
    }

    public function getHash(): string
    {
        return $this->hash;
    }

    public function getType(): ?TokenType
    {
        return $this->type;
    }

    public function setType(TokenType $type): static
    {
        $this->type = $type;

        return $this;
    }

    public function getExpiresAt(): ?\DateTimeImmutable
    {
        return $this->expires_at;
    }

    public function setExpiresAt(\DateTimeImmutable $expires_at): static
    {
        $this->expires_at = $expires_at;

        return $this;
    }

    public function isUsed(): bool
    {
        return $this->used;
    }

    public function setUsed(): static
    {
        $this->used = true;

        return $this;
    }

    public function getCreatedAt(): \DateTimeImmutable
    {
        return $this->created_at;
    }
}
