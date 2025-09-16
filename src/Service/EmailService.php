<?php
namespace App\Service;

use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Email;

class EmailService
{
	public function __construct(
        #[Autowire('%app.email.info%')] private readonly string $originAddress,
		private readonly MailerInterface $mailer,
	) {}
    public function send(string $address, string $subject, string $body): void
    {
        $email = (new Email())
            ->from($this->originAddress)
            ->to($address)
            ->subject($subject)
            ->text($body);
        $this->mailer->send($email);
    }

	public function sendPasswordResetEmail(string $email, string $username, string $token): void
    {
        $subject = "Reset your password";
        $body = $this->buildPasswordResetTemplate($username, $token);
        
        $this->send($email, $subject, $body);
    }
	private function buildPasswordResetTemplate(string $username, string $token): string
    {
        // In a real app, you'd have a proper frontend URL
        $resetUrl = "http://localhost:80/reset-password.php?token={$token}";
        
        return "
            <h2>Password Reset Request</h2>
            <p>Hi {$username},</p>
            <p>You requested a password reset. Click the link below to reset your password:</p>
            <p><a href='{$resetUrl}' style='display: inline-block; padding: 10px 20px; background-color: #007bff; color: white; text-decoration: none; border-radius: 4px;'>Reset Password</a></p>
            <p>Or copy this link: {$resetUrl}</p>
            <p><small>This link will expire in 30 minutes. If you didn't request this, please ignore this email.</small></p>
        ";
    }

    public function sendWelcomeEmail(string $email, string $username, string $token): void
    {
        $subject = "Welcome to our platform!";
        $body = $this->buildWelcomeTemplate($username, $token);
        
        $this->send($email, $subject, $body);
    }
    private function buildWelcomeTemplate(string $username, string $token): string
    {
        $activationUrl = "http://localhost:80/guest/activate-account?token={$token}";
        return "
            <h2>Welcome {$username}!</h2>
            <p>Your account has been successfully created.</p>
            <p>Click the link below to activate it:</p>
            <p><a href='{$activationUrl}' style='display: inline-block; padding: 10px 20px; background-color: #007bff; color: white; text-decoration: none; border-radius: 4px;'>Activate account</a></p>
            <p>Or copy this link: {$activationUrl}</p>
            <p><small>This link will expire in 30 minutes. If you didn't request this, please ignore this email.</small></p>
        ";
    }
}