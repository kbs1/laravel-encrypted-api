<?php

namespace Kbs1\EncryptedApi\Console\Commands;

use Illuminate\Console\Command;

class GenerateSharedSecretsCommand extends Command
{
	protected $signature = 'encrypted-api:secrets:generate';
	protected $description = 'Generate suitable shared secrets for the Encrypted API package.';

	public function handle()
	{
		$this->callSilent('vendor:publish', ['--tag' => 'encrypted-api']);

		list($secret1, $secret2) = $this->generateSharedSecrets();

		try {
			$config = $this->replaceSharedSecrets($this->loadDefaultConfiguration(), $secret1, $secret2);
			$this->writeConfiguration($config);
		} catch (UnableToLoadDefaultConfigurationException $ex) {
			$this->error('Unable to load default package configuration.');
			return 1;
		} catch (UnableToSaveConfigurationException $ex) {
			$this->error('Unable to write config/encrypted_api.php config file.');
			return 1;
		}

		$this->info('Generation complete! Shared secrets were stored in config/encrypted_api.php config file.');
	}

	protected function generateSharedSecrets()
	{
		do {
			$secret1 = openssl_random_pseudo_bytes(32);
			$secret2 = openssl_random_pseudo_bytes(32);
		} while (hash_equals($secret1, $secret2));

		return [$this->binaryToStorableString($secret1), $this->binaryToStorableString($secret2)];
	}

	protected function binaryToStorableString($binary)
	{
		$string = '';

		foreach (str_split($binary) as $byte) {
			$ord = ord($byte);
			if ($ord == 39)
				$string .= '\\\'';
			else if ($ord < 32 || $ord > 126)
				$string .= '\x' . ($ord < 17 ? '0' : '' ) . dechex($ord);
			else
				$string .= $byte;
		}

		return $string;
	}

	protected function loadDefaultConfiguration()
	{
		$config = @file_get_contents(__DIR__ . '/../../../config/encrypted_api.php');
		if ($config === false)
			throw new UnableToLoadDefaultConfigurationException();

		return $config;
	}

	protected function replaceSharedSecrets($config, $secret1, $secret2)
	{
		return str_replace([
			"'secret1' => ''",
			"'secret2' => ''",
			"'ipv4_whitelist' => null",
		], [
			"'secret1' => '$secret1'",
			"'secret2' => '$secret2'",
			"'ipv4_whitelist' => " . var_export(config('encrypted_api.ipv4_whitelist'), true),
		], $config);
	}

	protected function writeConfiguration($config)
	{
		if (@file_put_contents(config_path('encrypted_api.php'), $config) === false)
			throw new UnableToSaveConfigurationException();
	}
}

class GenerateSharedSecretsCommandException extends \Exception {}
class UnableToLoadDefaultConfigurationException extends GenerateSharedSecretsCommandException {}
class UnableToSaveConfigurationException extends GenerateSharedSecretsCommandException {}
