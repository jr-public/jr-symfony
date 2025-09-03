<?php
namespace App\Command;

use App\Enum\UserRole;
use App\Service\UserService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

#[AsCommand(name: 'app:seed')]
class SeedCommand extends Command
{
    public function __construct(
		private readonly EntityManagerInterface $em,
		private readonly UserService $userService
	) 
    {
        parent::__construct();
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
		$create = $this->userService->create("admin", "admin@email.com", "1234", UserRole::Admin);
		$this->userService->activateAccount($create['token']);

		$create = $this->userService->create("nonActivatedUser", "nonActivatedUser@email.com", "1234", UserRole::User);

		$create = $this->userService->create("user", "user@email.com", "1234", UserRole::User);
		$this->userService->activateAccount($create['token']);

        // $user = new User(UserRole::Admin);
		// $user->setUsername("admin");
		// $user->setEmail("admin@email.com");
		// $hashedPassword = $this->passwordHasher->hashPassword($user, "1234");
		// $user->setPassword($hashedPassword);
        // $this->em->persist($user);

        // $this->em->flush();

        $output->writeln('Seeding complete!');
        return Command::SUCCESS;
    }
}
