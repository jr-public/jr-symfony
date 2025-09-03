<?php
namespace App\DTO;

use Symfony\Component\Validator\Constraints as Assert;

class UserPatchDTO
{
    #[Assert\NotBlank]
    #[Assert\Choice(['username','email'])]
    public string $property;
    #[Assert\NotBlank]
    public mixed $value;
}