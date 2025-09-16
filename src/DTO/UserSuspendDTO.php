<?php
namespace App\DTO;

use Symfony\Component\Validator\Constraints as Assert;

class UserSuspendDTO
{
    public ?\DateTimeImmutable $until;
}