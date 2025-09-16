<?php
namespace Tests\Service;

use App\Service\EmailService;
use PHPUnit\Framework\MockObject\MockObject;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Email;

/**
 * @group unit
 */
final class EmailServiceTest extends WebTestCase
{
    private EmailService $emailService;
    private MockObject&MailerInterface $mailerMock;
    private string $originAddress = 'noreply@example.com';

    protected function setUp(): void
    {
        parent::setUp();
        $this->mailerMock = $this->createMock(MailerInterface::class);
        $this->emailService = new EmailService(
            $this->originAddress,
            $this->mailerMock
        );
    }

    public function testSendDispatchesEmail(): void
    {
        $to = 'john@example.com';
        $subject = 'Test subject';
        $body = 'Test body';

        $this->mailerMock
            ->expects($this->once())
            ->method('send')
            ->with($this->callback(function (Email $email) use ($to, $subject, $body) {
                $this->assertSame($this->originAddress, $email->getFrom()[0]->getAddress());
                $this->assertSame($to, $email->getTo()[0]->getAddress());
                $this->assertSame($subject, $email->getSubject());
                $this->assertStringContainsString($body, $email->getTextBody());
                return true;
            }));

        $this->emailService->send($to, $subject, $body);
    }

    public function testSendPasswordResetEmailBuildsCorrectEmail(): void
    {
        $to = 'jane@example.com';
        $username = 'Jane';
        $token = 'reset_token_123';

        $this->mailerMock
            ->expects($this->once())
            ->method('send')
            ->with($this->callback(function (Email $email) use ($to, $username, $token) {
                $this->assertSame($this->originAddress, $email->getFrom()[0]->getAddress());
                $this->assertSame($to, $email->getTo()[0]->getAddress());
                $this->assertSame('Reset your password', $email->getSubject());
                $this->assertStringContainsString("Hi {$username}", $email->getTextBody() ?? $email->getHtmlBody());
                $this->assertStringContainsString($token, $email->getTextBody() ?? $email->getHtmlBody());
                return true;
            }));

        $this->emailService->sendPasswordResetEmail($to, $username, $token);
    }

    public function testSendWelcomeEmailBuildsCorrectEmail(): void
    {
        $to = 'mark@example.com';
        $username = 'Mark';
        $token = 'activation_token_456';

        $this->mailerMock
            ->expects($this->once())
            ->method('send')
            ->with($this->callback(function (Email $email) use ($to, $username, $token) {
                $this->assertSame($this->originAddress, $email->getFrom()[0]->getAddress());
                $this->assertSame($to, $email->getTo()[0]->getAddress());
                $this->assertSame('Welcome to our platform!', $email->getSubject());
                $this->assertStringContainsString("Welcome {$username}", $email->getTextBody() ?? $email->getHtmlBody());
                $this->assertStringContainsString($token, $email->getTextBody() ?? $email->getHtmlBody());
                return true;
            }));

        $this->emailService->sendWelcomeEmail($to, $username, $token);
    }
}
