<?php

namespace InnerServe\PostfixAPI;

use Symfony\Component\ClassLoader\UniversalClassLoader;

define('API_VERSION', '0.1');
define('API_AUTHOR', 'Jeremi Bergman <jeremib@gmail.com>');

define('DB_HOST', '');
define('DB_USER', '');
define('DB_PASS', '');
define('DB_DATABASE', '');

require_once __DIR__.'/../vendor/autoload.php';

$app = new \Silex\Application();

$loader = new UniversalClassLoader();
$loader->registerNamespace('InnerServe', __DIR__.'/../src/');
$loader->register();

// include controllers
require '../src/InnerServe/PostfixAPI/Controller/default.php';
require '../src/InnerServe/PostfixAPI/Controller/domain.php';
require '../src/InnerServe/PostfixAPI/Controller/mailbox.php';
// require '../src/Service/PostfixService.php';




$app['pdo'] = new \PDO(sprintf('mysql:host=%s;dbname=%s', DB_HOST, DB_DATABASE), DB_USER, DB_PASS);
$app['pdo']->setAttribute( \PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION );
$app['postfix_service'] = new \InnerServe\PostfixAPI\Service\PostfixService($app['pdo']);

$app['json_response'] = new \InnerServe\PostfixAPI\Service\JsonResponseService();

$app->register(new \Silex\Provider\SecurityServiceProvider(), array(
    'security.firewalls' => array(
	    'admin' => array(
	        'pattern' => '^/',
	        'http' => true,
	        'users' => array(
	            // raw password is foo
	            'admin' => array('ROLE_ADMIN', '5FZ2Z8QIkA7UTZ4BYkoC+GsReLf569mSKDsfods6LYQ8t+a8EW9oaircfMpmaLbPBh4FOBiiFyLfuZmTSUwzZg=='),
	        ),
	    )
	)
));



$app->run();

