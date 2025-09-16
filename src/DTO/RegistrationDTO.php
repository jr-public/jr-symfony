<?php
namespace App\DTO;

use Symfony\Component\Validator\Constraints as Assert;

class RegistrationDTO
{
    #[Assert\NotBlank]
    public string $username;
    #[Assert\NotBlank]
    #[Assert\Email]
    public string $email;
    #[Assert\NotBlank]
    public string $password;
}