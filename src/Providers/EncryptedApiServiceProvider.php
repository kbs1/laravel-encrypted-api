<?php

namespace Kbs1\EncryptedApi\Providers;

use Illuminate\Support\ServiceProvider;
use Illuminate\Routing\Router;

use Kbs1\EncryptedApi\Http\Middleware\EncryptedApi;

class EncryptedApiServiceProvider extends ServiceProvider
{
	public function boot(Router $router)
	{
		$this->publishes([__DIR__ . '/../../config/encrypted_api.php' => config_path('encrypted_api.php')], 'encrypted-api');

		$router->aliasMiddleware('kbs1.encryptedApi', EncryptedApi::class);
	}

	public function register()
	{
		$this->mergeConfigFrom(__DIR__ . '/../../config/encrypted_api.php', 'encrypted_api');
	}
}
