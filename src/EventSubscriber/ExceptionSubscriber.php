<?php
namespace App\EventSubscriber;

use App\Exception\ApiException;
use App\Exception\ValidationException;
use App\Service\ResponseBuilder;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\ExceptionEvent;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;

class ExceptionSubscriber implements EventSubscriberInterface
{
    public function __construct(
        #[Autowire(env: 'APP_DEBUG')] private readonly int $isDebugEnabled,
        private readonly ResponseBuilder $responseBuilder
    ) {}
    public static function getSubscribedEvents(): array
    {
        return [
            ExceptionEvent::class => [
                ['onKernelException', 0],
            ],
        ];
    }
    public function onKernelException(ExceptionEvent $event): void
    {
        $throwable = $event->getThrowable();
        if ($throwable instanceof BadRequestHttpException) {
            $valException = new ValidationException('VALIDATION_EXCEPTION', $throwable->getMessage(), 400);
            $response = $this->responseBuilder->error($valException, $valException->getHttpStatus());
        }
        elseif ($throwable instanceof ApiException) {
            $response = $this->responseBuilder->error($throwable, $throwable->getHttpStatus());
        }
        else {
            $response = $this->responseBuilder->error($throwable, 500);
        }
        $event->setResponse($response);
    }
}