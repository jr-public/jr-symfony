<?php
namespace App\Security;

use App\Entity\User;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAccountStatusException;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Core\User\UserInterface;

class UserChecker implements UserCheckerInterface
{
    public function checkPreAuth(UserInterface $user): void
    {
        if (!$user instanceof User) {
            throw new AccessDeniedException('Invalid user type');
            return;
        }

        if (!$user->isActivated()) {
            throw new CustomUserMessageAccountStatusException('Account pending activation');
        }
        if ($user->isSuspended()) {
            throw new CustomUserMessageAccountStatusException('Account suspended');
        }
    }

    public function checkPostAuth(UserInterface $user): void
    {
        if (!$user instanceof User) {
            throw new AccessDeniedException('Invalid user type');
            return;
        }
    }
}