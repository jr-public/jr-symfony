<?php
namespace App\EventSubscriber;

use App\Service\ExceptionMapperService;
use App\Service\ResponseBuilder;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\ExceptionEvent;

class ExceptionSubscriber implements EventSubscriberInterface
{
    public function __construct(
        private readonly ExceptionMapperService $exceptionMapper,
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
        $apiException = $this->exceptionMapper->map($event->getThrowable());
        $response = $this->responseBuilder->error($apiException, $apiException->getHttpStatus());
        $event->setResponse($response);
    }
}