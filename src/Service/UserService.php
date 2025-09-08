<?php
namespace App\Service;

use App\Entity\User;
use App\Enum\TokenType;
use App\Enum\UserRole;
use App\Exception\BusinessException;
use App\Repository\UserRepository;
use Doctrine\DBAL\Exception\UniqueConstraintViolationException;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;

class UserService
{
	public function __construct(
		private readonly EntityManagerInterface $entityManager,
		private readonly TokenService $tokenService,
        private readonly UserRepository $userRepo,
        private readonly UserPasswordHasherInterface $passwordHasher,
		private readonly EmailService $emailService
	) {}
    public function get(int $id): ?User
    {
        $options = ["id" => $id];
        return $this->userRepo->findOneBy($options);
    }
    public function setUsername(User $user, string $username): User
    {
        $user->setUsername($username);
        $this->entityManager->flush();
        return $user;
    }
    public function setEmail(User $user, string $email): User
    {
        $user->setEmail($email);
        $this->entityManager->flush();
        return $user;
    }
    public function index(array $filters): array
    {
        $result = $this->userRepo->findWithFilters($filters);
        return $result;
    }
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
            throw new BusinessException('USER_CREATION_FAILED', 'UNIQUE_CONSTRAINT');
        }

        $token = $this->tokenService->createToken(TokenType::ActivateAccount, $user);
        $this->emailService->sendWelcomeEmail($user->getEmail(), $user->getUsername(), $token);
		return [
			'token' => $token,
			'user' 	=> $user->toArray()
		];
    }
    public function delete(User $user): void
    {
        $this->entityManager->remove($user);
        $this->entityManager->flush();
    }
    public function suspend(User $user, \DateTimeImmutable $until): void
    {
        $user->setSuspendedUntil($until);
        $this->entityManager->flush();
    }
    public function unsuspend(User $user): void
    {
        $user->setSuspendedUntil(null);
        $this->entityManager->flush();
    }

	public function login(User $user): array
	{
        $identifier = $user->getEmail();
		$token 	= $this->tokenService->createSessionJwt($identifier);
		return [
			'token' => $token,
			'user' 	=> $user->toArray()
		];
	}
    public function activateAccount(string $token): void
    {
        $user = $this->tokenService->verifyToken($token, TokenType::ActivateAccount);
        $user->activate();
        $this->entityManager->flush();
    }
	public function forgotPassword(string $email): ?string
    {
        $user = $this->userRepo->findOneBy(['email' =>$email]);
        if ($user && $user->isActivated()) {
            $token = $this->tokenService->createToken(TokenType::ForgotPassword, $user);
            $this->emailService->sendPasswordResetEmail($user->getEmail(), $user->getUsername(), $token);
			return $token;
        }
		return null;
    }
    public function resetPassword(string $token, string $password): void
    {
        $user = $this->tokenService->verifyToken($token, TokenType::ForgotPassword);
        $hashedPassword = $this->passwordHasher->hashPassword($user, $password);
        $user->setPassword($hashedPassword);
        $this->entityManager->flush();
    }
    public function resendActivation(string $email): ?string
    {
        $user = $this->userRepo->findOneBy(['email'=>$email]);
        if ($user && !$user->isActivated()) {
            $token = $this->tokenService->createToken(TokenType::ActivateAccount, $user);
            $this->emailService->sendWelcomeEmail($user->getEmail(), $user->getUsername(), $token);
			return $token;
        }
		return null;
    }
}