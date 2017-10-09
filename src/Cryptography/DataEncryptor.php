<?php

namespace Kbs1\EncryptedApi\Cryptography;

use Kbs1\EncryptedApi\Exceptions\EncryptedApiException;

class DataEncryptor extends Base
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
		$iv = $this->getRandomBytes($this->getIvLength());

		$data = [
			'id' => $this->used_id = $this->force_id ?? $this->getRandomBytes($this->getIdLength()),
			'timestamp' => time(),
			'data' => $this->getData(),
			'url' => $this->url,
			'method' => strtolower($this->method),
			'headers' => $this->headers,
		];

		$encrypted = bin2hex(openssl_encrypt(is_array($data) ? json_encode($data) : $data, $this->getDataAlgorithm(), $this->getSecret1(), 0, hex2bin($iv)));
		$signature = hash_hmac($this->getSignatureAlgorithm(), $encrypted . $iv, $this->getSecret2());

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
