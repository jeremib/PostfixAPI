<?php

namespace InnerServe\PostfixAPI\Exception;

class MailboxNotFoundException extends \Exception {
	public function __construct($username, $domain) {
		parent::__construct(sprintf("Username '%s' on Domain '%s' not found.", $username, $domain));
	}
}