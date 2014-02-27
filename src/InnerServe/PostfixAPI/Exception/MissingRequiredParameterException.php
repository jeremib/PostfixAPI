<?php

namespace InnerServe\PostfixAPI\Exception;

class MissingRequiredParameterException extends \Exception {
	public function __construct($parameter) {
		parent::__construct(sprintf("Required Parameter '%s' is missing", $parameter));
	}
}