<?php
namespace App\Security;

use App\Entity\User;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\Voter;

class UserVoter extends Voter
{
    public const DELETE = 'USER_DELETE';
    public const EDIT = 'USER_EDIT';
    public const SUSPEND = 'USER_SUSPEND';

    protected function supports(string $attribute, mixed $subject): bool
    {
        return $subject instanceof User && in_array($attribute, [
            self::DELETE,
            self::EDIT,
            self::SUSPEND,
        ], true);
    }

    protected function voteOnAttribute(string $attribute, mixed $subject, TokenInterface $token): bool
    {
        $currentUser = $token->getUser();
        if (!$currentUser instanceof User) {
            return false;
        }

        switch ($attribute) {
            case self::DELETE:
                return $this->canDelete($subject, $currentUser);
            case self::EDIT:
                return $this->canEdit($subject, $currentUser);
            case self::SUSPEND:
                return $this->canSuspend($subject, $currentUser);
        }

        return false;
    }

    private function canDelete(User $target, User $current): bool
    {
        if (!in_array('ROLE_ADMIN', $current->getRoles(), true)) {
            return $target->getId() === $current->getId();
        }

        if (in_array('ROLE_ADMIN', $target->getRoles(), true)) {
            return $target->getId() === $current->getId();
        }

        return true;
    }
    private function canEdit(User $target, User $current): bool
    {
        // 1. Regular users can only edit themselves
        if (!in_array('ROLE_ADMIN', $current->getRoles(), true)) {
            return $target->getId() === $current->getId();
        }

        // Current user is an Admin at this point.
        
        // 2. An Admin can never edit another Admin.
        if (in_array('ROLE_ADMIN', $target->getRoles(), true)) {
            return $target->getId() === $current->getId();
        }

        // 3. Admin editing a non-Admin (Regular User). This is allowed.
        return true;
    }

    private function canSuspend(User $target, User $current): bool
    {
        // Example: admins can suspend users, but not other admins
        return in_array('ROLE_ADMIN', $current->getRoles(), true)
            && !in_array('ROLE_ADMIN', $target->getRoles(), true);
    }
}