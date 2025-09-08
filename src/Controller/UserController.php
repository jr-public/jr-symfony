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
use Symfony\Component\Security\Http\Attribute\IsGranted;

final class UserController extends AbstractController
{
    public function __construct(
        private readonly ResponseBuilder $responseBuilder,
        private readonly UserService $userService
    ) {}
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
    #[Route('/user/{id}', name: 'user_get', methods: ['GET'])]
    #[OA\Response(
        response: 200,
        description: 'Returns a user.'
    )]
    public function get(User $target): JsonResponse
    {
        return $this->responseBuilder->success($target->toArray());
    }
    #[Route('/user/{id}', name: 'user_patch', methods: ['PATCH'])]
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
        return $this->responseBuilder->success($target->toArray());
    }
    #[Route('/user/{id}', name: 'user_delete', methods: ['DELETE'])]
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
    #[Route('/user/{id}/suspend', name: 'user_suspend', methods: ['POST'])]
    #[IsGranted('USER_SUSPEND', subject: 'target')]
    #[OA\Response(
        response: 200,
        description: 'Suspends a user.'
    )]
    public function suspend(#[MapRequestPayload] UserSuspendDTO $dto, User $target): JsonResponse
    {
        $this->denyAccessUnlessGranted('USER_SUSPEND', $target);
        $this->userService->suspend($target, $dto->until);
        return $this->responseBuilder->success();
    }
    #[Route('/user/{id}/unsuspend', name: 'user_unsuspend', methods: ['POST'])]
    #[IsGranted('USER_SUSPEND', subject: 'target')]
    #[OA\Response(
        response: 200,
        description: 'Unsuspends a user.'
    )]
    public function unsuspend(User $target): JsonResponse
    {
        $this->denyAccessUnlessGranted('USER_SUSPEND', $target);
        $this->userService->unsuspend($target);
        return $this->responseBuilder->success();
    }
}
