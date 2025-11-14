<?php

declare(strict_types=1);

namespace App\Service;

use App\Exception\ApiException;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\HttpFoundation\JsonResponse;

/**
 * Class ResponseBuilder
 *
 * A utility class for building standardized JSON responses.
 * Provides methods to create success and error responses with consistent structure.
 *
 * @package App\Service
 */
final class ResponseBuilder
{
    /**
     * ResponseBuilder constructor.
     *
     * @param string $environment The application environment (e.g., 'dev', 'prod').
     * @param int $internalErrorStatus The HTTP status code to use for internal server errors.
     * @param string $internalErrorString The default error message string for internal errors.
     */

    public function __construct(
        #[Autowire(env: 'APP_ENV')] private readonly string $environment,
        private readonly int $internalErrorStatus = JsonResponse::HTTP_INTERNAL_SERVER_ERROR,
        private readonly string $internalErrorString = 'INTERNAL_ERROR'
    ) {}

    /**
     * Creates a successful JSON response with optional data.
     *
     * @param array|null $data The data to include in the response, or null if no data is provided.
     * @return JsonResponse A JSON response with the data and no error.
     */
    public function success(?array $data = null): JsonResponse
    {
        // Return a standardized success response with data and null error
        return new JsonResponse([
            'data'  => $data,
            'error' => null,
        ]);
    }

    /**
     * Creates an error JSON response based on the provided exception.
     *
     * @param \Throwable $exception The exception that triggered the error response.
     * @param int $status The HTTP status code for the response.
     * @return JsonResponse A JSON response with error details and no data.
     */
    public function error(\Throwable $exception, ?int $status = null): JsonResponse
    {
        // If status is null or invalid, default to internal server error
        if ($status === null || $status < 100 || $status > 599) {
            $status = $this->internalErrorStatus;
        }

        // Build error array with timestamp and message
        $error = [
            'timestamp' => date('c'), // ISO 8601 formatted timestamp
            'message'   => ($exception instanceof ApiException) ? $exception->getMessage() : $this->internalErrorString,
        ];

        // Add more detailed error information in development environment
        if ($this->environment != 'prod') {
            $error = array_merge($error, [
                'method'    => $_SERVER['REQUEST_METHOD'] ?? 'unknown',
                'uri'       => $_SERVER['REQUEST_URI'] ?? 'unknown',
            ]);
            if ($exception instanceof ApiException) {
                $error = array_merge($error, $exception->toArray());
            }
            else {
                $error = array_merge($error, [
                    'class'     => get_class($exception),
                    'message'   => $exception->getMessage(),
                    'status'    => $exception->getCode(),
                    'file'      => $exception->getFile(),
                    'line'      => $exception->getLine(),
                    'trace'     => $exception->getTrace(),
                ]);
            }
        }
        // Return a standardized error response with null data and error details
        return new JsonResponse([
            'data'  => null,
            'error' => $error,
        ], $status);
    }
}