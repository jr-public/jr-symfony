<?php
namespace App\Entity;

use App\Enum\UserRole;
use App\Repository\UserRepository;
use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Core\User\UserInterface;

#[ORM\Entity(repositoryClass: UserRepository::class)]
#[ORM\Table(name: 'users')]
#[ORM\UniqueConstraint(name: 'UNIQ_IDENTIFIER_EMAIL', fields: ['email'])]
#[ORM\Index(columns: ['username'])]
#[ORM\Index(columns: ['suspended_until'])]
class User implements UserInterface, PasswordAuthenticatedUserInterface
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private int $id;

    #[ORM\Column(length: 255)]
    private string $username;

    #[ORM\Column(length: 180)]
    private string $email;

    #[ORM\Column]
    private array $roles = [];

    #[ORM\Column]
    private string $password;

    #[ORM\Column]
    private bool $isActivated = false;

    #[ORM\Column(nullable: true)]
    private ?\DateTimeImmutable $suspended_until = null;
    
    #[ORM\Column]
    private \DateTimeImmutable $created_at;


    public function __construct(UserRole $role)
    {
        $this->created_at = new \DateTimeImmutable();
        $this->roles = [UserRole::User->value];
        if (!in_array($role->value, $this->roles)) {
            $this->roles[] = $role->value;
        }
    }
    public function toArray(): array {
        $array = [
            'id'                => $this->getId(),
            'username'          => $this->getUsername(),
            'email'             => $this->getEmail(),
            'roles'             => $this->getRoles(),
            'isActivated'       => $this->isActivated(),
            'suspendedUntil'    => $this->getSuspendedUntil()?->format(\DateTimeInterface::ATOM), // ISO 8601 format
            'createdAt'         => $this->getCreatedAt()?->format(\DateTimeInterface::ATOM), // ISO 8601 format
        ];
        return $array;
    }
    public function getId(): ?int
    {
        return $this->id;
    }

    public function getEmail(): ?string
    {
        return $this->email;
    }

    public function setEmail(string $email): static
    {
        $this->email = $email;

        return $this;
    }

    /**
     * A visual identifier that represents this user.
     *
     * @see UserInterface
     */
    public function getUserIdentifier(): string
    {
        return (string) $this->email;
    }

    /**
     * @see UserInterface
     */
    public function getRoles(): array
    {
        $roles = $this->roles;
        return $roles;
    }
    /**
     * @see PasswordAuthenticatedUserInterface
     */
    public function getPassword(): ?string
    {
        return $this->password;
    }

    public function setPassword(string $password): static
    {
        $this->password = $password;

        return $this;
    }

    /**
     * Ensure the session doesn't contain actual password hashes by CRC32C-hashing them, as supported since Symfony 7.3.
     */
    public function __serialize(): array
    {
        $data = (array) $this;
        $data["\0".self::class."\0password"] = hash('crc32c', $this->password);

        return $data;
    }

    #[\Deprecated]
    public function eraseCredentials(): void
    {
        // @deprecated, to be removed when upgrading to Symfony 8
    }

    public function getUsername(): ?string
    {
        return $this->username;
    }

    public function setUsername(string $username): static
    {
        $this->username = $username;

        return $this;
    }

    public function getCreatedAt(): \DateTimeImmutable
    {
        return $this->created_at;
    }

    public function isActivated(): bool
    {
        return $this->isActivated;
    }

    public function activate(): static
    {
        if (!$this->isActivated) {
            $this->isActivated = true;
        }
        return $this;
    }
    public function isSuspended(): bool
    {
        if (!$this->suspended_until) {
            return false;
        }
        if ($this->suspended_until < new \DateTimeImmutable) {
            return false;
        }
        return true;
    }
    public function getSuspendedUntil(): ?\DateTimeImmutable
    {
        return $this->suspended_until;
    }

    public function setSuspendedUntil(?\DateTimeImmutable $suspended_until): static
    {
        $this->suspended_until = $suspended_until;

        return $this;
    }
}
