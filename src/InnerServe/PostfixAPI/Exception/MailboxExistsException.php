<?php

namespace InnerServe\PostfixAPI\Exception;

class MailboxExistsException extends \Exception {
	public function __construct($username, $domain) {
		parent::__construct(sprintf("Username '%s' on Domain '%s' already exists.", $username, $domain));
	}
}