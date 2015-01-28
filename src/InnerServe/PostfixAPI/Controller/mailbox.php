<?php
namespace PostfixAPI\Controller;

use Symfony\Component\HttpFoundation\Request;


$mailbox = $app['controllers_factory'];

$mailbox->get('/create/', function() use ($app) {
	return $app['json_response']->error('Username cannot be empty.'); 
});

$mailbox->get('/create/{username}/{domain}', function($username, $domain, Request $request) use ($app) {
	try {
		return $app['json_response']->ok($app['postfix_service']->createMailbox($username, $request->get('password'), $domain, $request->get('name'), $request->get('q')));	
	} catch(\Exception $e) {
		return $app['json_response']->error($e->getMessage());
	}
	
});

$mailbox->get('/list/{domain}', function($domain) use ($app) {
	try {
		return $app['json_response']->ok($app['postfix_service']->getMailboxes($domain));	
	} catch(\Exception $e) {
		return $app['json_response']->error($e->getMessage());
	}
});

// mount to the application
$app->mount('/mailbox', $mailbox);
