<?php
namespace App\EventSubscriber;

use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\RateLimiter\RateLimiterFactoryInterface;

class RequestSubscriber implements EventSubscriberInterface
{
    public function __construct(
        private readonly RateLimiterFactoryInterface $mainLimiter,
        #[Autowire('%env(APP_ENV)%')] private readonly string $environment,
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
        if ($this->environment === 'test') {
            return;
        }
        $identifier = $event->getRequest()->getClientIp();
        $limiter    = $this->mainLimiter->create($identifier);
        $limiter->consume(1)->ensureAccepted();
    }
}