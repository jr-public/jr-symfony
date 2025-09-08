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
        // Only admin can delete, not themselves, only regular users
        if (!in_array('ROLE_ADMIN', $current->getRoles(), true)) {
            return false;
        }

        if ($target->getId() === $current->getId()) {
            return false;
        }

        return !in_array('ROLE_ADMIN', $target->getRoles(), true);
    }

    private function canEdit(User $target, User $current): bool
    {
        // Maybe admins can edit anyone, users can only edit themselves
        if (in_array('ROLE_ADMIN', $current->getRoles(), true)) {
            return true;
        }

        return $target->getId() === $current->getId();
    }

    private function canSuspend(User $target, User $current): bool
    {
        // Example: admins can suspend users, but not other admins
        return in_array('ROLE_ADMIN', $current->getRoles(), true)
            && !in_array('ROLE_ADMIN', $target->getRoles(), true);
    }
}