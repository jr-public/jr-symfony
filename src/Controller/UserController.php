<?php

namespace App\Controller;

use App\DTO\UserListFiltersDTO;
use App\DTO\UserPatchDTO;
use App\DTO\UserSuspendDTO;
use App\Entity\User;
use App\Service\ResponseBuilder;
use App\Service\UserService;
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
    public function index(#[MapQueryString()] UserListFiltersDTO $dto): JsonResponse
    {
        $users = $this->userService->index($dto);
        return $this->responseBuilder->success($users);
    }
    #[Route('/user/{id}', name: 'user_get', methods: ['GET'])]
    public function get(User $target): JsonResponse
    {
        return $this->responseBuilder->success($target->toArray());
    }
    #[Route('/user/{id}', name: 'user_patch', methods: ['PATCH'])]
    #[IsGranted('USER_EDIT', subject: 'target')]
    public function patch(#[MapRequestPayload] UserPatchDTO $dto, User $target): JsonResponse
    {
        $target = $this->userService->patch($target, $dto->property, $dto->value);
        return $this->responseBuilder->success($target->toArray());
    }
    #[Route('/user/{id}', name: 'user_delete', methods: ['DELETE'])]
    #[IsGranted('USER_DELETE', subject: 'target')]
    public function delete(User $target): JsonResponse
    {
        $this->userService->delete($target);
        return $this->responseBuilder->success();
    }
}
