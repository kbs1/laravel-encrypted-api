<?php

namespace Kbs1\EncryptedApi\Cryptography;

use Kbs1\EncryptedApi\Exceptions\EncryptedApiException;

class Encryptor extends Base
{
	protected $force_id, $used_id, $headers, $url, $method;

	public function __construct($data, $secret1, $secret2, $force_id = null, $headers = null, $url = null, $method = null)
	{
		$this->force_id = $force_id;
		$this->headers = $headers;
		$this->url = $url;
		$this->method = $method;
		parent::__construct($data, $secret1, $secret2);
	}

	public function encrypt()
	{
		$iv = $this->getRandomBytes($this->iv_length);

		$data = [
			'id' => $this->used_id = $this->force_id ?? $this->getRandomBytes($this->id_length),
			'timestamp' => time(),
			'data' => $this->data,
			'url' => $this->url,
			'method' => strtolower($this->method),
			'headers' => $this->headers,
		];

		$encrypted = bin2hex(openssl_encrypt(is_array($data) ? json_encode($data) : $data, $this->data_algorithm, $this->getSecret1(), 0, hex2bin($iv)));
		$signature = hash_hmac($this->signature_algorithm, $encrypted . $iv, $this->getSecret2());

		$this->checkDataFormat($encrypted);
		$this->checkIvFormat($iv);
		$this->checkSignatureFormat($signature);
		$this->checkIdFormat($this->getId());

		return json_encode(['data' => $encrypted, 'iv' => $iv, 'signature' => $signature]);
	}

	public function getId()
	{
		return $this->used_id;
	}
}
