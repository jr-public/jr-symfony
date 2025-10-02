<?php
namespace App\Exception;

class ApiException extends \Exception {
    protected ?string $detail;
    protected int $httpStatus;
    protected ?\Throwable $thrownBy = null;

    public function __construct(
        string $message = 'API_ERROR',
        ?string $detail = null,
        int $httpStatus = 500
    ) {
        parent::__construct($message, $httpStatus);
        $this->httpStatus = $httpStatus;
        $this->detail = $detail;
    }
    public function toArray(): array {
        $array = [
            'class'     => get_class($this),
            'message'   => $this->getMessage(),
            'detail'    => $this->getDetail(),
            'status'    => $this->getHttpStatus(),
            'file'      => $this->getFile(),
            'line'      => $this->getLine(),
        ];
        $thrownBy = $this->getThrownBy();
        if ($thrownBy) {
            $array['thrownBy'] = [
                'class'     => get_class($thrownBy),
                'message'   => $thrownBy->getMessage(),
                'status'      => $thrownBy->getCode(),
                'file'      => $thrownBy->getFile(),
                'line'      => $thrownBy->getLine(),
            ];
        }
        return $array;
    }
    public function getDetail(): ?string {
        if (empty($this->detail)) {
            return $this->message;
        }
        return $this->detail;
    }
    public function getHttpStatus(): int {
        return $this->httpStatus;
    }
    public function setThrownBy(\Throwable $throwable): void {
        $this->thrownBy = $throwable;
    }
    public function getThrownBy(): ?\Throwable {
        return $this->thrownBy;
    }
}
