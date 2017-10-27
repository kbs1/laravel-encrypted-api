<?php

namespace Kbs1\EncryptedApi\Cryptography;

use Kbs1\EncryptedApi\Exceptions\EncryptedApiException;

class Decryptor extends Base
{
	public function decrypt()
	{
		$input = $this->parse();
		$this->verifySignature($input);
		$decrypted = $this->decryptData($input);
		$this->checkIdFormat($decrypted->id);
		$this->verifyTimestamp($decrypted);

		return $decrypted;
	}

	protected function parse()
	{
		$input = json_decode($this->data);
		$this->checkJsonDecodeSuccess();

		if (!property_exists($input, 'signature') || !property_exists($input, 'iv') || !property_exists($input, 'data'))
			throw new InvalidDataException();

		$this->checkSignatureFormat($input->signature);
		$this->checkIvFormat($input->iv);
		$this->checkDataFormat($input->data);

		return $input;
	}

	protected function verifySignature($input)
	{
		$expected = hash_hmac($this->signature_algorithm, $input->data . $input->iv, $this->getSecret2());

		if (!hash_equals($expected, $input->signature))
			throw new InvalidSignatureException();
	}

	protected function decryptData($input)
	{
		$decrypted = @openssl_decrypt(hex2bin($input->data), $this->data_algorithm, $this->getSecret1(), OPENSSL_RAW_DATA, hex2bin($input->iv));

		if ($decrypted === false)
			throw new InvalidDataException();

		$decrypted = json_decode($decrypted);
		$this->checkJsonDecodeSuccess();

		if (!property_exists($decrypted, 'id') || !property_exists($decrypted, 'timestamp') || !property_exists($decrypted, 'data')
			|| !property_exists($decrypted, 'url') || !property_exists($decrypted, 'method')|| !property_exists($decrypted, 'headers'))
			throw new InvalidDataException();

		return $decrypted;
	}

	protected function verifyTimestamp($data)
	{
		if (!is_numeric($data->timestamp) || $data->timestamp < time() - 10)
			throw new InvalidTimestampException();
	}

	protected function checkJsonDecodeSuccess()
	{
		if (json_last_error() !== JSON_ERROR_NONE)
			throw new InvalidDataException();
	}
}

class InvalidTimestampException extends EncryptedApiException {}
