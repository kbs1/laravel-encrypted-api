<?php

namespace Kbs1\EncryptedApi\Http;

use Kbs1\EncryptedApi\Cryptography\DataDecryptor;
use Kbs1\EncryptedApi\Exceptions\EncryptedApiException;

class IncomingRequest
{
	protected $decryptor, $request, $id;

	public function __construct($request, $secret1, $secret2)
	{
		$this->decryptor = new DataDecryptor($request->getContent(), $secret1, $secret2);
		$this->request = $request;
	}

	public function decrypt()
	{
		$input = $this->decryptor->decrypt();
		$this->id = $input->id;

		$this->checkRequestId($input);
		$this->checkUrl($input);
		$this->checkMethod($input);

		$data = $input->data;
		$this->request->merge(json_decode(json_encode($data), true));
	}

	public function getId()
	{
		return $this->id;
	}

	protected function checkRequestId()
	{
		$dir = storage_path('encrypted_api_requests');

		if (file_exists($dir) && !is_dir($dir))
			throw new ReplayAttacksProtectionException('File is not a directory: ' . $dir);

		if (!file_exists($dir) && !@mkdir($dir))
			throw new ReplayAttacksProtectionException('Unable to create directory: ' . $dir);

		$request_id_file = @fopen($dir . '/' . $this->getId(), 'x');
		if ($request_id_file === false)
			throw new RequestIdAlreadyProcessedException();

		$files = glob($dir . '/*');
		$now = time();

		foreach ($files as $file)
			if (is_file($file) && $now - filemtime($file) > 10)
				unlink($file);

		fclose($request_id_file);
	}

	protected function checkUrl($input)
	{
		if ($this->request->fullUrl() !== $input->url)
			throw new InvalidRequestUrlException();
	}

	protected function checkMethod($input)
	{
		if (strtolower($this->request->method()) !== $input->method)
			throw new InvalidRequestMethodException();
	}
}

class ReplayAttacksProtectionException extends EncryptedApiException {}
class RequestIdAlreadyProcessedException extends EncryptedApiException {}
class InvalidRequestUrlException extends EncryptedApiException {}
class InvalidRequestMethodException extends EncryptedApiException {}
