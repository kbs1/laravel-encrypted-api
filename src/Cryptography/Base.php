<?php

namespace Kbs1\EncryptedApi\Cryptography;

use Kbs1\EncryptedApi\Exceptions\EncryptedApiException;

class Base
{
	protected $data, $secret1, $secret2;

	protected $data_algorithm = 'aes-256-ctr';
	protected $signature_algorithm = 'ripemd320';
	protected $signature_length = 40;
	protected $id_length = 20;
	protected $shared_secret_minimum_length = 16;

	public function __construct($data, $secret1, $secret2)
	{
		$this->data = $data;
		$this->secret1 = $secret1;
		$this->secret2 = $secret2;
	}

	public function getData()
	{
		return $this->data;
	}

	public function getSecret1()
	{
		$this->checkSharedSecretFormat($this->secret1);
		$this->checkSharedSecretsAreNotEqual();
		return $this->secret1;
	}

	public function getSecret2()
	{
		$this->checkSharedSecretFormat($this->secret2);
		$this->checkSharedSecretsAreNotEqual();
		return $this->secret2;
	}

	protected function getDataAlgorithm()
	{
		return $this->data_algorithm;
	}

	protected function getSignatureAlgorithm()
	{
		return $this->signature_algorithm;
	}

	protected function getSignatureLength()
	{
		return $this->signature_length;
	}

	protected function getSignatureLengthInHexNotation()
	{
		return $this->getSignatureLength() * 2;
	}

	protected function getIvLength()
	{
		return openssl_cipher_iv_length($this->getDataAlgorithm());
	}

	protected function getIvLengthInHexNotation()
	{
		return $this->getIvLength() * 2;
	}

	protected function getIdLength()
	{
		return $this->id_length;
	}

	protected function getIdLengthInHexNotation()
	{
		return $this->getIdLength() * 2;
	}

	protected function checkDataFormat($data)
	{
		if (!$this->checkBinHexFormat($data))
			throw new InvalidDataException();
	}

	protected function checkIvFormat($iv)
	{
		if (!$this->checkBinHexFormat($iv, $this->getIvLengthInHexNotation()))
			throw new InvalidIvException();
	}

	protected function checkSignatureFormat($signature)
	{
		if (!$this->checkBinHexFormat($signature, $this->getSignatureLengthInHexNotation()))
			throw new InvalidSignatureException();
	}

	protected function checkIdFormat($id)
	{
		if (!$this->checkBinHexFormat($id, $this->getIdLengthInHexNotation()))
			throw new InvalidIdException();
	}

	protected function checkSharedSecretFormat($secret)
	{
		 if (strlen($secret) < $this->shared_secret_minimum_length)
			throw new InvalidSharedSecretException();
	}

	protected function checkSharedSecretsAreNotEqual()
	{
		if (hash_equals($this->secret1, $this->secret2))
			throw new InvalidSharedSecretException();
	}

	protected function checkBinHexFormat($value, $length = null)
	{
		return preg_match('/^[\da-f]' . ($length ? '{' . $length . '}' : '+') . '$/siu', $value);
	}

	protected function getRandomBytes($length)
	{
		$bytes = openssl_random_pseudo_bytes($length, $is_strong);
		if (!$is_strong)
			throw new WeakRandomBytesException();

		return bin2hex($bytes);
	}
}

class InvalidDataException extends EncryptedApiException {}
class InvalidIvException extends EncryptedApiException {}
class InvalidSignatureException extends EncryptedApiException {}
class InvalidIdException extends EncryptedApiException {}
class InvalidSharedSecretException extends EncryptedApiException {}
class WeakRandomBytesException extends EncryptedApiException {}
