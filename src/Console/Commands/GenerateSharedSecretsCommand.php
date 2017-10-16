<?php

namespace Kbs1\EncryptedApi\Console\Commands;

use Illuminate\Console\Command;

class GenerateSharedSecretsCommand extends Command
{
	protected $signature = 'encrypted-api:secrets:generate {--save : Overwrite current config/encrypted_api.php with generated secrets. IPv4 whitelist will be preserved.}';
	protected $description = 'Generate suitable shared secrets for the Encrypted API package.';

	public function handle()
	{
		$this->callSilent('vendor:publish', ['--tag' => 'encrypted-api']);

		list($secret1, $secret2) = $this->generateSharedSecrets();

		if (!$this->option('save')) {
			$this->info('Generation complete! Place the following shared secrets in config/encrypted_api.php config file:');
			$this->line("\t'secret1' => \"$secret1\",\n\t'secret2' => \"$secret2\",\n");
			return;
		}

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

		return [$this->binaryToOneLinePhpString($secret1), $this->binaryToOneLinePhpString($secret2)];
	}

	protected function binaryToOneLinePhpString($binary)
	{
		$string = '';

		foreach (str_split($binary) as $byte) {
			$ord = ord($byte);
			if ($ord == 34 || $ord == 36 || $ord == 92)
				$string .= '\\' . $byte;
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
			"'secret1' => \"$secret1\"",
			"'secret2' => \"$secret2\"",
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
