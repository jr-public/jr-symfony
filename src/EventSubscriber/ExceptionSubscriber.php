<?php
namespace App\EventSubscriber;

use App\Service\ResponseBuilder;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\ExceptionEvent;
use Symfony\Component\HttpKernel\KernelEvents;

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
        if (!$this->isDebugEnabled) {
            $response = $this->responseBuilder->error($event->getThrowable());
            $event->setResponse($response);
        }
    }
}