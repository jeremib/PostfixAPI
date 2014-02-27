<?php

namespace InnerServe\PostfixAPI\Exception;

class DomainAlreadyExistsException extends \Exception {
	public function __construct($domain) {
		parent::__construct(sprintf("Domain '%s' already exists.", $domain));
	}
}