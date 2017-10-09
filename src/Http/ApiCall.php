<?php

namespace Kbs1\EncryptedApi\Http;

use Kbs1\EncryptedApi\Cryptography\DataEncryptor;
use Kbs1\EncryptedApi\Cryptography\DataDecryptor;
use Kbs1\EncryptedApi\Exceptions\EncryptedApiException;
use Illuminate\Support\Collection;

class ApiCall
{
	protected $encryptor, $url, $method, $secret1, $secret2;
	protected $response, $httpStatus, $headers;

	public function __construct($url, $method = 'GET', $data = null, $secret1 = null, $secret2 = null)
	{
		$this->url = $url;
		$this->method = $method;
		$this->secret1 = $secret1 ?? config('encrypted_api.secret1');
		$this->secret2 = $secret2 ?? config('encrypted_api.secret2');
		$this->encryptor = new DataEncryptor($data instanceof Collection ? $data->toArray() : (is_array($data) ? $data : []), $this->secret1, $this->secret2, null, null, $url, $method);
	}

	public function execute()
	{
		$options = [
			'http' => [
				'header'  => "Content-type: application/json\r\nAccept: application/json\r\n",
				'method'  => strtoupper($this->method),
				'content' => $this->encryptor->encrypt(),
				'ignore_errors' => true,
			]
		];

		$response = @file_get_contents($this->url, false, stream_context_create($options));

		if ($response === false)
			throw new UnableToReadUrlException();

		$header = $http_response_header[0] ?? 'HTTP/1.1 200 OK';
		$parts = explode(' ', $header);
		$this->httpStatus = $parts[1] ?? 200;

		$response = (new DataDecryptor($response, $this->secret1, $this->secret2))->decrypt();
		$this->response = $response->data;
		$this->parseResponseHeaders($response->headers);

		if (!hash_equals($this->encryptor->getId(), $response->id))
			throw new InvalidResponseIdException();

		return $this->response;
	}

	public function response()
	{
		return $this->response;
	}

	public function httpStatus()
	{
		return $this->httpStatus;
	}

	public function headers()
	{
		return $this->headers;
	}

	protected function parseResponseHeaders($headers)
	{
		$this->headers = [];
		$headers = explode("\r\n", $headers);

		foreach ($headers as $header) {
			$colon_pos = strpos($header, ':');
			if ($colon_pos !== false) {
				$header_name = substr($header, 0, $colon_pos);
				$header_value = substr($header, $colon_pos + 1);
				$this->headers[trim($header_name)] = trim($header_value);
			}
		}
	}
}

class ApiCallException extends EncryptedApiException {}
class UnableToReadUrlException extends ApiCallException {}
class InvalidResponseIdException extends ApiCallException {}
