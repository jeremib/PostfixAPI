<?php

namespace InnerServe\PostfixAPI\Exception;

class DomainMailboxSizeExceededException extends \Exception {
	public function __construct() {
		parent::__construct("Mailbox size exceeds domain max quota.");
	}
}