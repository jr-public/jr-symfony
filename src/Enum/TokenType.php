<?php
namespace App\Enum;

enum TokenType: string
{
	case ActivateAccount = 'activate-account';
	case ForgotPassword = 'forgot-password';
}
