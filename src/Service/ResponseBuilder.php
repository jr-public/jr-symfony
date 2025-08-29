<?php
namespace App\Service;

use App\Exception\ApiException;
use Symfony\Component\HttpFoundation\JsonResponse;

class ResponseBuilder
{
    public function success(?array $data = null): JsonResponse
    {
        return new JsonResponse([
            'data'   => $data,
            'error' => null,
        ]);
    }
    public function error(\Throwable $exception, int $status = JsonResponse::HTTP_BAD_REQUEST): JsonResponse
    {
        $error = [
                'timestamp' => date('c'),
                'message'   => ($exception instanceof ApiException)?$exception->getDetail():$exception->getMessage(),
                'method'    => $_SERVER['REQUEST_METHOD'] ?? 'unknown',
                'uri'       => $_SERVER['REQUEST_URI'] ?? 'unknown',
                'class'     => get_class($exception),
                'file'      => $exception->getFile(),
                'line'      => $exception->getLine(),
                'trace'     => $exception->getTrace(),
            ];
        
        return new JsonResponse([
            'data'   => null,
            'error' => $error,
        ], $status);
    }
}
