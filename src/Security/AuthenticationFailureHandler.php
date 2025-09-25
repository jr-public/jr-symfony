<?php
namespace App\Security;

use App\Exception\AuthException;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;

class AuthenticationFailureHandler implements AuthenticationFailureHandlerInterface
{
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): JsonResponse
    {
        $message = $exception->getMessage();
        // These strings seem to be built into symfony
        if ($message === 'Bad credentials.') {
            throw new AuthException('AUTH_ERROR', 'BAD_EMAIL', 401);
        }
        elseif ($message === 'The presented password is invalid.') {
            throw new AuthException('AUTH_ERROR', 'BAD_PASS', 401);
        }
        // Handle uncaught exceptions
        else {
            throw $exception;
        }
    }
}