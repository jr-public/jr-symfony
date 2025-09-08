<?php
namespace App\Security;

use App\Entity\User;
use App\Exception\AuthException;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Core\User\UserInterface;

class UserChecker implements UserCheckerInterface
{
    public function checkPreAuth(UserInterface $user): void
    {
        if (!$user instanceof User) {
            throw new AuthException('AUTH_ERROR', 'BAD_USER_TYPE', 500);
        }
    }

    public function checkPostAuth(UserInterface $user): void
    {
        if (!$user instanceof User) {
            throw new AuthException('AUTH_ERROR', 'BAD_USER_TYPE', 500);
        }

        if (!$user->isActivated()) {
            throw new AuthException('AUTH_ERROR', 'INACTIVE_USER', 401);
        }
        if ($user->isSuspended()) {
            throw new AuthException('AUTH_ERROR', 'SUSPENDED_USER', 403);
        }
    }
}