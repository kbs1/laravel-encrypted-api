# Laravel Encrypted API
Create encrypted API communication between Laravel applications in a breeze. Request and response data is transmitted securely using a two-way cipher,
everything is checksummed to prevent modification (MITM attacks) in any way.

This package is meant to be used in both the client and server applications. Since it handles both receiving the request (verifying and decrypting)
and sending a request / response (encrypting and signing), the whole implementation is seamless and based only on a middleware.

The middleware transparently modifies the incoming request and replaces the request data with decrypted values, so you can use your own
`FormRequest`s, validation or any other code that you would normally use with a standard request (for example `$request->input('foo')`
inside controllers and so on).

You can extend the middleware to satisfy any specific needs you might have (for example multiple clients communicating securely each with it's own set
of shared secrets).

The called API routes should be served using HTTPS for extra security, but this is not a requirement.

This package authenticates the calling client, since no other caller knows the shared secrets. This ensures your API is securely called only
from applications under your or approved 3rd party control, even if the API routes themselves are publicly open to the internet.

## Installation
```
composer require kbs1/laravel-encrypted-api
```
The package is now installed. If you are using laravel version &lt; 5.5, add the following line in your `config/app.php` providers section:
```
Kbs1\EncryptedApi\Providers\EncryptedApiServiceProvider::class,
```

## Configuration
By default, the package supports encrypted communication with exactly one client, with one pair of shared secrets. First publish the config using
`php artisan vendor:publish --tag=encrypted-api` and set the appropriate `secret1` and `secret2` values (minimum 32 bytes in length, for `secret1`,
only the first 32 bytes are used). Do the same in your other application and you are ready to go!

For your convenience, `php artisan encrypted-api:secrets:generate` command is included to generate suitable shared secrets, or generate new ones.
This command automatically publishes the config if it hasn't been published already. After executing, you can view the generated secrets by
opening `config/encrypted_api.php` - copy the shared secrets to your other application and configuration is complete!

## Usage
Once the package is installed, it automatically registers the `kbs1.encryptedApi` middleware alias.
You can use this alias in any routes you would like to secure using this package.

### Receiving requests (server application)
```
Route::group(['prefix' => '/api', 'middleware' => ['kbs1.encryptedApi']], function () {
	Route::post('/users/disable', 'App\Http\Controllers\Api\UsersController@disable')->name('myApp.api.users.disable');
	...
});
```
Above example automatically secures the route group using this package, any calls to the group must now be sent only using authenticated client application.
Default middleware implementation uses shared secrets defined in `config/encrypted_api.php`.

You can easily support multiple calling clients with secrets stored for example in a database. Extend the
`Kbs1\EncryptedApi\Http\Middleware\EncryptedApi` class and implement your own `getSharedSecrets()` method:
```
class ClientApi extends \Kbs1\EncryptedApi\Http\Middleware\EncryptedApi
{
	protected function getSharedSecrets($request)
	{
		$client = \App\Clients\ClientRepository::findByUuid($request->route('clientUuid'));
		return ['secret1' => $client->secret1, 'secret2' => $client->secret2];
	}
}
```
In the above example, the route group might look like this:
```
Route::group(['prefix' => '/api/{clientUuid}', 'middleware' => ['clientApi']], function () {
	Route::post('/users/disable', 'App\Http\Controllers\Api\Clients\UsersController@disable')->name('myApp.api.clients.users.disable');
	...
});
```

### Sending requests (caller application)
Calling encrypted API service can be accomplished in the following way:
```
$call = new \Kbs1\EncryptedApi\Http\ApiCall("https://server-application.dev/api/$ourUuid/users/disable", 'POST', [
	'user_uuid' => '...',
	'parameter1' => true,
	'parameter2' => 'foo',
	...
], $secret1, $secret2);

try {
	$response = $call->execute(); // will execute the call each time invoked
} catch (\Kbs1\EncryptedApi\Exceptions\EncryptedApiException $ex) {
	...
}

// retrieve service response later if desired
$response = $call->response();
$http_status_code = $call->httpStatus();
$response_headers = $call->headers();
```
`$response` will contain any response sent by the service. This might be JSON or any other service response you implement. All service responses protected
by this package are always properly signed and encrypted before sending, even if an exception occurs (invalid request data, crashes in your service
and so on). This means no one, without knowing the required shared secrets, is able to read the service response in any case.

`ApiCall` constructor can take either collection or array as the third optional data argument.
Fourth and fifth arguments (`secret1` and `secret2`) are optional as well and if they are omitted, shared secrets are loaded
from `config/encrypted_api.php` file.

For `GET` requests, the package will send a request body as well. This ensures the request must also be properly signed, and no one except the authorised
caller can call the route.

### A note on query string and route parameters
It is adivsed to send each API service parameter using third (data) argument of the `ApiCall` class only (even for GET requests).
Althrough the package verifies the exact URL that was called (including query string and HTTP method) on the server side, sensitive data passed as
query parameters or route segments can still be captured for example in server's access log.

Securely passed parameters (third data argument) always overwrite query string paramets, using Laravel's `$request->merge()` method.

The only parameter that is advised to be passed as query string parameter or route segment is the `clientUuid` parameter, should you have multiple calling
clients. As this parameter is used to load shared secrets for particular client, it can not be passed encrypted.

### IP whitelists
If you want to ensure API calls from a certain client come only from whitelisted IPv4 addresses, you can set appropriate `ipv4_whitelist` array in
`config/encrypted_api.php`. To provide your own whitelist based on `clientUuid` or any other client identifier (when you have multiple calling clients),
override `getAllowedIps` method in your own route middleware class:
```
class ClientApi extends \Kbs1\EncryptedApi\Http\Middleware\EncryptedApi
{
	protected function getAllowedIps($request)
	{
		$client = \App\Clients\ClientRepository::findByUuid($request->route('clientUuid'));
		return [$client->ipv4];
	}
}
```

## Replay attacks
This package protects using simple replay attacks, as each signed request and response has it's unique identifier, and is only valid for 10 seconds.
Implementation automatically stores each received identifier in the last 10 seconds on the server side, and discards any processing when encountering
already processed request identifier.
