<?php
namespace App\DTO;

use Symfony\Component\Validator\Constraints as Assert;

class EmailDTO
{
    #[Assert\NotBlank]
    #[Assert\Email]
    public string $email;
}