<?php
namespace App\DTO;

use Symfony\Component\Validator\Constraints as Assert;

class UserSuspendDTO
{
    #[Assert\NotBlank]
    public \DateTimeImmutable $until;
}