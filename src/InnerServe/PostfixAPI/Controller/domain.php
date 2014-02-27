<?php
use Symfony\Component\HttpFoundation\Request;


$domain = $app['controllers_factory'];

$domain->get('/create/', function() use ($app) {
	return $app['json_response']->error('Domain cannot be empty.'); 
});

$domain->get('/create/{domain}', function($domain, Request $request) use ($app) {
	try {
		return $app['json_response']->ok($app['postfix_service']->createDomain($domain, $request->get('maxaliases'), $request->get('maxmailboxes'), $request->get('maxquota')));
	} catch(\Exception $e) {
		return $app['json_response']->error($e->getMessage());
	}
	
});

$domain->get('/list', function() use ($app) {
	return $app['json_response']->ok($app['postfix_service']->getDomains());
});

$domain->get('/get/{domain}', function($domain) use ($app) {
	return $app['json_response']->ok($app['postfix_service']->getDomainInfo($domain));
});

// mount to the application
$app->mount('/domain', $domain);
