<?php
namespace App\Security;

use App\Service\TokenService;
use Symfony\Component\Security\Http\AccessToken\AccessTokenHandlerInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;

class AccessTokenHandler implements AccessTokenHandlerInterface
{
    public function __construct(
        private readonly TokenService $tokenService
    ) {}

    public function getUserBadgeFrom(string $accessToken): UserBadge
    {
        $decoded = $this->tokenService->decodeSessionJwt($accessToken);
        return new UserBadge($decoded->sub);
    }
}