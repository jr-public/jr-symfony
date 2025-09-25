<?php
namespace App\EventSubscriber;

use App\Exception\ApiException;
use App\Service\ResponseBuilder;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\ExceptionEvent;

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
        if ($throwable instanceof ApiException) {
            $response = $this->responseBuilder->error($throwable, $throwable->getHttpStatus());
        }
        else {
            $response = $this->responseBuilder->error($throwable, 500);
        }
        $event->setResponse($response);
    }
}