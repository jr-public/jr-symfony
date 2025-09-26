<?php

namespace App\Controller;

use App\DTO\EmailDTO;
use App\DTO\RegistrationDTO;
use App\DTO\ResetPasswordDTO;
use App\Entity\User;
use App\Enum\UserRole;
use App\Service\ResponseBuilder;
use App\Service\UserService;
use OpenApi\Attributes AS OA;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpKernel\Attribute\MapRequestPayload;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\CurrentUser;

/**
 * Controller for unauthenticated user actions, such as login, registration, and password management.
 */
final class GuestController extends AbstractController
{
    /**
     * @param ResponseBuilder $responseBuilder Builds standard API responses.
     * @param UserService $userService Manages user-related business logic.
     */
    public function __construct(
        private readonly ResponseBuilder $responseBuilder,
        private readonly UserService $userService
    ) {}

    /**
     * Authenticates a user and returns an authentication token.
     *
     * @param User $user The authenticated user object from the security context.
     * @return JsonResponse
     */
    #[Route('/guest/login', name:'guest_login', methods: ['POST'])]
    #[OA\RequestBody(
        required: true,
        content: new OA\JsonContent(
            properties: [
                new OA\Property(
                    property: 'email',
                    type: 'string',
                    example: 'user@example.com'
                ),
                new OA\Property(
                    property: 'password',
                    type: 'string',
                    example: 'Password123!'
                )
            ],
            type: 'object'
        )
    )]
    #[OA\Response(
        response: 200,
        description: 'Returns the authenticated user and an authorization token.'
    )]
    public function login(#[CurrentUser] User $user): JsonResponse
    {
        $login = $this->userService->login($user);
        $response = $this->responseBuilder->success($login);
        return $response;
    }

    /**
     * Registers a new user.
     *
     * @param RegistrationDTO $dto Contains user registration details.
     * @return JsonResponse
     */
    #[Route('/guest/registration', name:'guest_registration', methods: ['POST'])]
    #[OA\Response(
        response: 200,
        description: 'Returns a new user and an activation token.'
    )]
    public function registration(#[MapRequestPayload] RegistrationDTO $dto): JsonResponse
    {
        $create = $this->userService->create(
            $dto->username,
            $dto->email,
            $dto->password,
            UserRole::User
        );
        $response   = $this->responseBuilder->success($create);
        return $response;
    }

    /**
     * Activates a user account using an activation token.
     *
     * @param string $token The activation token from the URL.
     * @return JsonResponse
     */
    #[Route('/guest/activate-account/{token}', name:'guest_activate_account', methods: ['GET'])]
    #[OA\Parameter(
        name: 'token',
        description: 'The activation token for the user account.',
        in: 'path',
        required: true,
        schema: new OA\Schema(type: 'string'),
        example: 'activation_token123'
    )]
    #[OA\Response(
        response: 200,
        description: 'Activates the user account.'
    )]
    public function activateAccount(string $token): JsonResponse
    {
        $this->userService->activateAccount($token);
        return $this->responseBuilder->success();
    }

    /**
     * Initiates the password reset process by sending an email.
     *
     * @param EmailDTO $dto Data transfer object with the user's email address.
     * @return JsonResponse
     */
    #[Route('/guest/forgot-password', name:'guest_forgot_password', methods: ['POST'])]
    #[OA\Response(
        response: 200,
        description: 'Sends a password reset email to the user.'
    )]
    public function forgotPassword(#[MapRequestPayload] EmailDTO $dto): JsonResponse
    {
        $token = $this->userService->forgotPassword($dto->email);
        return $this->responseBuilder->success(['token' => $token]);
    }

    /**
     * Resets a user's password using a token and new password.
     *
     * @param ResetPasswordDTO $dto Data transfer object with the token and new password.
     * @return JsonResponse
     */
    #[Route('/guest/reset-password', name:'guest_reset_password', methods: ['POST'])]
    #[OA\Response(
        response: 200,
        description: 'Updates the user password.'
    )]
    public function resetPassword(#[MapRequestPayload] ResetPasswordDTO $dto): JsonResponse
    {
        $this->userService->resetPassword($dto->token, $dto->password);
        return $this->responseBuilder->success();
    }

    /**
     * Resends the activation email to a user.
     *
     * @param EmailDTO $dto Data transfer object with the user's email address.
     * @return JsonResponse
     */
    #[Route('/guest/resend-activation', name:'guest_resend_activation', methods: ['POST'])]
    #[OA\Response(
        response: 200,
        description: 'Sends another activation email to the user.'
    )]
    public function resendActivation(#[MapRequestPayload] EmailDTO $dto): JsonResponse
    {
        $this->userService->resendActivation($dto->email);
        return $this->responseBuilder->success();
    }
}