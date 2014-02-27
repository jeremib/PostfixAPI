<?php
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\HttpKernelInterface;


$default = $app['controllers_factory'];

$default->get('/', function() use ($app) {
	return $app->handle(Request::create('/about', 'GET'), HttpKernelInterface::SUB_REQUEST);
});

$default->get('/about', function() use ($app) {
	return returnOkResult(array(
		'version' => API_VERSION,
		'author' => API_AUTHOR
		));
});

$app->mount('/', $default);