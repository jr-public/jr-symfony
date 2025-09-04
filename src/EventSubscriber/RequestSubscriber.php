<?php
namespace App\EventSubscriber;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\RateLimiter\RateLimiterFactoryInterface;
class RequestSubscriber implements EventSubscriberInterface
{
    public function __construct(
        private readonly RateLimiterFactoryInterface $mainLimiter,
    ) {}
    public static function getSubscribedEvents(): array
    {
        return [
            RequestEvent::class => [
                ['onRequestApplyRateLimiting', 0],
            ],
        ];
    }
    public function onRequestApplyRateLimiting(RequestEvent $event): void
    {
        $identifier = $event->getRequest()->getClientIp();
        $limiter    = $this->mainLimiter->create($identifier);
        $limiter->consume(1)->ensureAccepted();
        // $limiter->reset();
    }
}