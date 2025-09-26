<?php
namespace App\Service;

use App\Entity\User;
use App\Enum\TokenType;
use App\Enum\UserRole;
use App\Exception\AuthException;
use App\Exception\BusinessException;
use App\Repository\UserRepository;
use Doctrine\DBAL\Exception\UniqueConstraintViolationException;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;

/**
 * Service class for managing user-related business logic and database interactions.
 */
class UserService
{
    /**
     * @param EntityManagerInterface $entityManager Manages entity persistence and flushing.
     * @param TokenService $tokenService Handles token creation and verification.
     * @param UserRepository $userRepo Provides access to user data from the database.
     * @param UserPasswordHasherInterface $passwordHasher Hashes user passwords securely.
     * @param EmailService $emailService Handles sending emails to users.
     */
    public function __construct(
        private readonly EntityManagerInterface $entityManager,
        private readonly TokenService $tokenService,
        private readonly UserRepository $userRepo,
        private readonly UserPasswordHasherInterface $passwordHasher,
        private readonly EmailService $emailService
    ) {}

    /**
     * Retrieves a single user by their ID.
     *
     * @param int $id The user's ID.
     * @return User|null The user object or null if not found.
     */
    public function get(int $id): ?User
    {
        $options = ["id" => $id];
        return $this->userRepo->findOneBy($options);
    }

    /**
     * Sets the username for a user and persists the change.
     *
     * @param User $user The user entity to modify.
     * @param string $username The new username.
     * @return User The updated user entity.
     */
    public function setUsername(User $user, string $username): User
    {
        $user->setUsername($username);
        $this->entityManager->flush();
        return $user;
    }

    /**
     * Sets the email address for a user and persists the change.
     *
     * @param User $user The user entity to modify.
     * @param string $email The new email address.
     * @return User The updated user entity.
     */
    public function setEmail(User $user, string $email): User
    {
        $user->setEmail($email);
        $this->entityManager->flush();
        return $user;
    }

    /**
     * Retrieves a list of users based on an array of filters.
     *
     * @param array $filters An associative array of filters.
     * @return array The array of user entities matching the filters.
     */
    public function index(array $filters): array
    {
        $result = $this->userRepo->findWithFilters($filters);
        return $result;
    }

    /**
     * Creates a new user account, hashes the password, and sends a welcome email.
     *
     * @param string $username The user's desired username.
     * @param string $email The user's email address.
     * @param string $password The user's plain-text password.
     * @param UserRole $role The role to assign to the new user.
     * @return array An array containing the activation token and the user's data.
     * @throws BusinessException If a unique constraint violation occurs (e.g., duplicate email or username).
     */
    public function create(string $username, string $email, string $password, UserRole $role = UserRole::User): array
    {
        try {
            $user = new User($role);
            $user->setUsername($username);
            $user->setEmail($email);
            $hashedPassword = $this->passwordHasher->hashPassword($user, $password);
            $user->setPassword($hashedPassword);
            $this->entityManager->persist($user);
            $this->entityManager->flush();
        } catch (UniqueConstraintViolationException $th) {
            throw new BusinessException('USER_CREATION_FAILED', 'UNIQUE_CONSTRAINT', 409);
        }

        $token = $this->tokenService->createToken(TokenType::ActivateAccount, $user);
        $this->emailService->sendWelcomeEmail($user->getEmail(), $user->getUsername(), $token);
        return [
            'token' => $token,
            'user'  => $user->toArray()
        ];
    }

    /**
     * Deletes a user account.
     *
     * @param User $user The user entity to remove.
     */
    public function delete(User $user): void
    {
        $this->entityManager->remove($user);
        $this->entityManager->flush();
    }

    /**
     * Suspends a user account until a specific date.
     *
     * @param User $user The user to suspend.
     * @param \DateTimeImmutable $until The date until which the account is suspended.
     */
    public function suspend(User $user, \DateTimeImmutable $until): void
    {
        $user->setSuspendedUntil($until);
        $this->entityManager->flush();
    }

    /**
     * Unsuspends a user account by removing the suspension date.
     *
     * @param User $user The user to unsuspend.
     */
    public function unsuspend(User $user): void
    {
        $user->setSuspendedUntil(null);
        $this->entityManager->flush();
    }

    /**
     * Creates a session JWT for an authenticated user upon successful login.
     *
     * @param User $user The authenticated user entity.
     * @return array An array containing the session token and the user's data.
     */
    public function login(User $user): array
    {
        $identifier = $user->getEmail();
        $token  = $this->tokenService->createSessionJwt($identifier);
        return [
            'token' => $token,
            'user'  => $user->toArray()
        ];
    }

    /**
     * Activates a user account using an activation token.
     *
     * @param string $token The activation token.
     */
    public function activateAccount(string $token): void
    {
        $user = $this->tokenService->verifyToken($token, TokenType::ActivateAccount);
        if ($user->isSuspended()) {
            throw new AuthException('AUTH_ERROR', 'USER_SUSPENDED', 403);
        }
        $user->activate();
        $this->entityManager->flush();
    }

    /**
     * Initiates the password reset process by sending a password reset email.
     *
     * @param string $email The user's email address.
     * @return string|null The password reset token or null if the user is not found or not activated.
     */
    public function forgotPassword(string $email): ?string
    {
        $user = $this->userRepo->findOneBy(['email' =>$email]);
        if ($user && !$user->isSuspended() && $user->isActivated()) {
            $token = $this->tokenService->createToken(TokenType::ForgotPassword, $user);
            $this->emailService->sendPasswordResetEmail($user->getEmail(), $user->getUsername(), $token);
            return $token;
        }
        return null;
    }

    /**
     * Resets a user's password using a token.
     *
     * @param string $token The password reset token.
     * @param string $password The new plain-text password.
     */
    public function resetPassword(string $token, string $password): void
    {
        $user = $this->tokenService->verifyToken($token, TokenType::ForgotPassword);
        if (!$user) {
            throw new AuthException('AUTH_ERROR', 'USER_NOT_FOUND', 401);
        }
        elseif ($user->isSuspended()) {
            throw new AuthException('AUTH_ERROR', 'USER_SUSPENDED', 401);
        }
        elseif (!$user->isActivated()) {
            throw new AuthException('AUTH_ERROR', 'USER_INACTIVE', 401);
        }
        $hashedPassword = $this->passwordHasher->hashPassword($user, $password);
        $user->setPassword($hashedPassword);
        $this->entityManager->flush();
    }

    /**
     * Resends the activation email to a user if their account is not yet activated.
     *
     * @param string $email The user's email address.
     * @return string|null The new activation token or null if the user is not found or already activated.
     */
    public function resendActivation(string $email): ?string
    {
        $user = $this->userRepo->findOneBy(['email'=>$email]);
        if ($user && !$user->isSuspended() && !$user->isActivated()) {
            $token = $this->tokenService->createToken(TokenType::ActivateAccount, $user);
            $this->emailService->sendWelcomeEmail($user->getEmail(), $user->getUsername(), $token);
            return $token;
        }
        return null;
    }
}