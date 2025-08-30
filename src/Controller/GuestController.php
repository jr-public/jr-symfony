<?php

namespace App\Controller;

use App\DTO\EmailDTO;
use App\DTO\RegistrationDTO;
use App\DTO\ResetPasswordDTO;
use App\Entity\User;
use App\Enum\UserRole;
use App\Service\ResponseBuilder;
use App\Service\UserService;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\MapRequestPayload;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\CurrentUser;

final class GuestController extends AbstractController
{
    public function __construct(
        private readonly ResponseBuilder $responseBuilder,
        private readonly UserService $userService
    ) {}
    #[Route('/guest/login', name:'guest_login', methods: ['POST'])]
    public function login(#[CurrentUser] User $user): JsonResponse
    {
        $login = $this->userService->login($user);
		$response = $this->responseBuilder->success($login);
        return $response;
    }
    #[Route('/guest/registration', name:'guest_registration', methods: ['POST'])]
    public function registration(#[MapRequestPayload] RegistrationDTO $dto): JsonResponse
    {
        $create = $this->userService->create(
            $dto->username,
            $dto->email,
            $dto->password,
            UserRole::User
        );
        $response 	= $this->responseBuilder->success($create);
        return $response;
    }
	#[Route('/guest/activate-account/{token}', name:'guest_activate_account', methods: ['GET'])]
    public function activateAccount(string $token): JsonResponse
    {
        $this->userService->activateAccount($token);
        return $this->responseBuilder->success();
    }
	#[Route('/guest/forgot-password', name:'guest_forgot_password', methods: ['POST'])]
    public function forgotPassword(#[MapRequestPayload] EmailDTO $dto): JsonResponse
    {
        $token = $this->userService->forgotPassword($dto->email);
        return $this->responseBuilder->success($token);
    }
	#[Route('/guest/reset-password', name:'guest_reset_password', methods: ['POST'])]
    public function resetPassword(#[MapRequestPayload] ResetPasswordDTO $dto): JsonResponse
    {
        $this->userService->resetPassword($dto->token, $dto->password);
        return $this->responseBuilder->success();
    }
	#[Route('/guest/resend-activation', name:'guest_resend_activation', methods: ['POST'])]
    public function resendActivation(#[MapRequestPayload] EmailDTO $dto): JsonResponse
    {
        $this->userService->resendActivation($dto->email);
        return $this->responseBuilder->success();
    }
}
