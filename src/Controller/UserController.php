<?php
namespace App\Controller;

use App\DTO\UserListFiltersDTO;
use App\DTO\UserPatchDTO;
use App\DTO\UserSuspendDTO;
use App\Entity\User;
use App\Service\ResponseBuilder;
use App\Service\UserService;
use OpenApi\Attributes AS OA;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpKernel\Attribute\MapQueryString;
use Symfony\Component\HttpKernel\Attribute\MapRequestPayload;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\CurrentUser;
use Symfony\Component\Security\Http\Attribute\IsGranted;

/**
 * Controller for managing user accounts by an authenticated user, typically an administrator.
 */
final class UserController extends AbstractController
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
     * Retrieves a paginated list of users, with optional filtering.
     *
     * @param UserListFiltersDTO $dto Filters for the user list.
     * @return JsonResponse
     */
    #[Route('/user', name: 'user_index', methods: ['GET'])]
    #[OA\Response(
        response: 200,
        description: 'Returns a filtered list of users.'
    )]
    public function index(#[MapQueryString()] UserListFiltersDTO $dto): JsonResponse
    {
        $users = $this->userService->index($dto->toArray());
        return $this->responseBuilder->success($users);
    }

    /**
     * Retrieves a single user's details by their ID.
     *
     * @param User $target The user entity to retrieve.
     * @return JsonResponse
     */
    #[Route('/user/{id}', name: 'user_get', methods: ['GET'], requirements: ['id' => '\d+'])]
    #[OA\Response(
        response: 200,
        description: 'Returns a user.'
    )]
    public function get(User $target): JsonResponse
    {
        return $this->responseBuilder->success(['user' => $target->toArray()]);
    }

    /**
     * Updates a single property of a user.
     *
     * @param UserPatchDTO $dto The data transfer object with the property to update and its new value.
     * @param User $target The user entity to modify.
     * @return JsonResponse
     */
    #[Route('/user/{id}', name: 'user_patch', methods: ['PATCH'], requirements: ['id' => '\d+'])]
    #[IsGranted('USER_EDIT', subject: 'target')]
    #[OA\Response(
        response: 200,
        description: 'Updates a users property.'
    )]
    public function patch(#[MapRequestPayload] UserPatchDTO $dto, User $target): JsonResponse
    {
        if ($dto->property == 'username')
        {
            $this->userService->setUsername($target, $dto->value);
        }
        elseif ($dto->property == 'email')
        {
            $this->userService->setEmail($target, $dto->value);
        }
        return $this->responseBuilder->success(['user' => $target->toArray()]);
    }

    /**
     * Deletes a user account.
     *
     * @param User $target The user entity to delete.
     * @return JsonResponse
     */
    #[Route('/user/{id}', name: 'user_delete', methods: ['DELETE'], requirements: ['id' => '\d+'])]
    #[IsGranted('USER_DELETE', subject: 'target')]
    #[OA\Response(
        response: 200,
        description: 'Deletes a user.'
    )]
    public function delete(User $target): JsonResponse
    {
        $this->userService->delete($target);
        return $this->responseBuilder->success();
    }

    /**
     * Suspends a user account until a specified date.
     *
     * @param UserSuspendDTO $dto Data transfer object with the suspension end date.
     * @param User $target The user entity to suspend.
     * @return JsonResponse
     */
    #[Route('/user/{id}/suspend', name: 'user_suspend', methods: ['POST'], requirements: ['id' => '\d+'])]
    #[IsGranted('USER_SUSPEND', subject: 'target')]
    #[OA\Response(
        response: 200,
        description: 'Suspends a user.'
    )]
    public function suspend(#[MapRequestPayload] UserSuspendDTO $dto, User $target): JsonResponse
    {
        $this->userService->suspend($target, $dto->until);
        return $this->responseBuilder->success();
    }

    /**
     * Unsuspends a user account.
     *
     * @param User $target The user entity to unsuspend.
     * @return JsonResponse
     */
    #[Route('/user/{id}/unsuspend', name: 'user_unsuspend', methods: ['POST'], requirements: ['id' => '\d+'])]
    #[IsGranted('USER_SUSPEND', subject: 'target')]
    #[OA\Response(
        response: 200,
        description: 'Unsuspends a user.'
    )]
    public function unsuspend(User $target): JsonResponse
    {
        $this->userService->unsuspend($target);
        return $this->responseBuilder->success();
    }
    /**
     * Returns a new session token.
     *
     * @param User $target The user entity to unsuspend.
     * @return JsonResponse
     */
    #[Route('/user/refresh', name: 'user_refresh', methods: ['POST'])]
    #[OA\Response(
        response: 200,
        description: 'Returns a new session token.'
    )]
    public function refresh(#[CurrentUser] User $user): JsonResponse
    {
        $result = $this->userService->login($user);
        $token = $result['token'];
        return $this->responseBuilder->success(['token' => $token]);
    }
}