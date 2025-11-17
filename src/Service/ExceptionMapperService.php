<?php

namespace App\Service;

use App\Exception\ApiException;
use Symfony\Component\DependencyInjection\Attribute\Autowire;

class ExceptionMapperService
{
	
	private array $indexed = [];
	
    public function __construct(
		#[Autowire('%app.exception.mapping%')] private readonly array $mapping
	) {
		foreach ($mapping as $map) {
			$this->indexed[$map['exception']][] = $map;
		}
	}

    public function map(\Throwable $throwable): ApiException
    {
		// We might get here already with an ApiException
		// I think the only place where this happens is in UserChecker
		if ($throwable instanceof ApiException) {
			return $throwable;
		}
		
		$config = null;
		$matches = $this->indexed[$throwable::class] ?? [];
		
		if (count($matches) > 1) {
			foreach ($matches as $match) {
				if ($match['error'] === $throwable->getMessage()) {
					$config = $match;
					break;
				}
			}
		}
		elseif (count($matches) == 1) {
			$config = $matches[0];		
		}
		
		if (empty($config)) { 
			$apiException = new ApiException('UNKNOWN_ERROR', $throwable->getMessage(), 500);
			$apiException->setThrownBy($throwable);
			return $apiException;
        }

		$apiException = new $config['apiException']($config['code'], $throwable->getMessage(), $config['status']);
		return $apiException;
    }
}