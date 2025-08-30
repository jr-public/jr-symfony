<?php
namespace App\DTO;

use Symfony\Component\Validator\Constraints as Assert;

class ResetPasswordDTO
{
    #[Assert\NotBlank]
    public string $token;
    #[Assert\NotBlank]
    public string $password;
}