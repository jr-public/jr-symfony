<?php
namespace App\Service;

use App\DTO\UserListFiltersDTO;
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
		// private readonly EmailService $emailService
	) {}
    public function get(int $id): ?User
    {
        $options = ["id" => $id];
        return $this->userRepo->findOneBy($options);
    }
    public function index(UserListFiltersDTO $filters): array
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
        // $this->emailService->sendWelcomeEmail($user->getEmail(), $user->getUsername(), $token);
		return [
			'token' => $token,
			'user' 	=> $user->toArray()
		];
    }
    public function patch(User $user, string $property, mixed $value): User
    {
        switch ($property) {
            case 'activate':
                $user->activate();
                break;
            case 'email':
                $user->setEmail($value);
                break;
            case 'password':
                $user->setPassword($value);
                break;
            case 'username':
                $user->setUsername($value);
                break;
            case 'suspendUntil':
                $user->setSuspendedUntil($value);
                break;
            default:
                return $user;
            }
        $this->entityManager->flush();
        return $user;
    }
    public function delete(User $user): void
    {
        $this->entityManager->remove($user);
        $this->entityManager->flush();
    }
    public function suspend(User $user, \DateTimeImmutable $until): void
    {
        $this->patch($user, 'suspendUntil', $until);
    }
    public function unsuspend(User $user): void
    {
        $this->patch($user, 'suspendUntil', null);
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
        $this->patch($user, 'activate', true);
    }
	public function forgotPassword(string $email): ?string
    {
        $user = $this->userRepo->findOneBy(['email' =>$email]);
        if ($user && $user->isActivated()) {
            $token = $this->tokenService->createToken(TokenType::ForgotPassword, $user);
            // $this->emailService->sendPasswordResetEmail($user->getEmail(), $user->getUsername(), $token);
			return $token;
        }
		return null;
    }
    public function resetPassword(string $token, string $password): void
    {
        $user = $this->tokenService->verifyToken($token, TokenType::ForgotPassword);
        $hashedPassword = $this->passwordHasher->hashPassword($user, $password);
        $this->patch($user, 'password', $hashedPassword);
    }
    public function resendActivation(string $email): ?string
    {
        $user = $this->userRepo->findOneBy(['email'=>$email]);
        if ($user && !$user->isActivated()) {
            $token = $this->tokenService->createToken(TokenType::ActivateAccount, $user);
            // $this->emailService->sendWelcomeEmail($user->getEmail(), $user->getUsername(), $token);
			return $token;
        }
		return null;
    }
}