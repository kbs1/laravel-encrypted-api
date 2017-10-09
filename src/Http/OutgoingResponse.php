<?php

namespace Kbs1\EncryptedApi\Http;

use Kbs1\EncryptedApi\Cryptography\DataEncryptor;

class OutgoingResponse
{
	protected $encryptor, $response;

	public function __construct($response, $secret1, $secret2, $id)
	{
		$this->encryptor = new DataEncryptor($response->content(), $secret1, $secret2, $id, (string) $response->headers);
		$this->response = $response;
	}

	public function encrypt()
	{
		$this->response->setContent($this->encryptor->encrypt());
		$this->response->header('Content-Type', 'application/json');
	}
}
