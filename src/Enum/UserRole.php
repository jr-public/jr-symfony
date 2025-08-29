<?php
namespace App\Enum;

enum UserRole: string
{
	case Admin = 'ROLE_ADMIN';
	case User = 'ROLE_USER';
}