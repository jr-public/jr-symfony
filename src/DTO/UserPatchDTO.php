<?php
namespace App\DTO;

use OpenApi\Attributes as OA;
use Symfony\Component\Validator\Constraints as Assert;

class UserPatchDTO
{
    #[Assert\NotBlank]
    #[Assert\Choice(['username','email'])]
    public string $property;
    #[OA\Property(type: 'array', items: new OA\Items(oneOf: [
        new OA\Schema(type: 'string'),
        // new OA\Schema(type: 'integer'),
        // new OA\Schema(type: 'boolean'),
    ]))]
    #[Assert\NotBlank]
    public string $value;
}