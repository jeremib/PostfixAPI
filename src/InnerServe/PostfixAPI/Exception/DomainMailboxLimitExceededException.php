<?php

namespace InnerServe\PostfixAPI\Exception;

class DomainMailboxLimitExceededException extends \Exception {
	public function __construct() {
		parent::__construct("Number of mailboxes exceeds domain max limit.");
	}
}