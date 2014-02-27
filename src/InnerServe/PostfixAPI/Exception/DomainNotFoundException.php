<?php

namespace InnerServe\PostfixAPI\Exception;

class DomainNotFoundException extends \Exception {
	public function __construct($domain) {
		parent::__construct(sprintf("Domain '%s' could not be found.", $domain));
	}
}