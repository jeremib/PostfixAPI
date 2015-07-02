<?php

namespace InnerServe\PostfixAPI\Exception;

class MailboxDoesNotExistException extends \Exception {
	public function __construct($username, $domain) {
		parent::__construct(sprintf("Username '%s' on Domain '%s' does not exist.", $username, $domain));
	}
}