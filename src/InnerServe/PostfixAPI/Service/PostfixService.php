<?php

namespace InnerServe\PostfixAPI\Service;

class PostfixService {
	private $pdo;

	public function __construct(\PDO $pdo) {
		$this->pdo = $pdo;
	}

	public function createDomain($domain, $maxaliases = 10, $maxmailboxes = 10, $maxquota = 1000) {
		if ( $this->isValidDomain($domain) ) {
			throw new \InnerServe\PostfixAPI\Exception\DomainAlreadyExistsException($domain);
		}

		if ( empty($maxaliases) || !is_numeric($maxaliases) ) {
			throw new \InnerServe\PostfixAPI\Exception\MissingRequiredParameterException('Max Aliases');	
		}

		if ( empty($maxmailboxes) || !is_numeric($maxmailboxes) ) {
			throw new \InnerServe\PostfixAPI\Exception\MissingRequiredParameterException('Max Mailboxes');	
		}

		if ( empty($maxquota) || !is_numeric($maxquota) ) {
			throw new \InnerServe\PostfixAPI\Exception\MissingRequiredParameterException('Max Quota');	
		}


		$stmt = $this->pdo->prepare("INSERT INTO 
			domain (domain, aliases, mailboxes, maxquota, transport, backupmx, created, modified, active)
			VALUES
			(:domain, :aliases, :mailboxes, :maxquota, :transport, :backupmx, :created, :modified, :active)");

		$stmt->execute(array(
			'domain' => $domain,
			'aliases' => intval($maxaliases),
			'mailboxes' => intval($maxmailboxes),
			'maxquota' => intval($maxquota),
			'transport' => 'virtual',
			'backupmx' => 0,
			'created' => date("Y-m-d H:i:s"),
			'modified' => date("Y-m-d H:i:s"),
			'active' => 1
			));
	}

	public function getMailboxes($domain) {
		if ( !$this->isValidDomain($domain) ) {
			throw new \InnerServe\PostfixAPI\Exception\DomainNotFoundException($domain);
		}

		$stmt = $this->pdo->prepare("SELECT username, name, (quota/1048576) quota, active, local_part FROM mailbox WHERE domain = :domain");
		$stmt->execute(array('domain' => $domain));
		return $stmt->fetchAll(\PDO::FETCH_ASSOC);		
	}

    public function getMailBox($local_part, $domain) {
        if ( !$this->isValidDomain($domain) ) {
            throw new \InnerServe\PostfixAPI\Exception\DomainNotFoundException($domain);
        }

        $stmt = $this->pdo->prepare("SELECT username, name, (quota/1048576) quota, active, local_part FROM mailbox WHERE domain = :domain AND local_part = :local_part");
        $stmt->execute(array('domain' => $domain, 'local_part' => $local_part));
        return $stmt->fetch(\PDO::FETCH_ASSOC);
    }

	/**
	 * Get list of domains on mail system
	 * @return array Array of domains 
	 */
	public function getDomains() {
		$stmt = $this->pdo->prepare('SELECT domain, description, aliases, mailboxes, maxquota, quota, active,
			(SELECT SUM(quota)/1048576 FROM mailbox m WHERE m.domain = d.domain) as actual_quota,
			(SELECT COUNT(*) FROM mailbox m WHERE m.domain = d.domain) as actual_mailboxes,
			(SELECT COUNT(*) FROM alias m WHERE m.domain = d.domain) as actual_aliases
			FROM domain d');
		$stmt->execute();
		return $stmt->fetchAll(\PDO::FETCH_ASSOC);
	}

    public function deleteMailbox($local_part, $domain) {
        if ( !$this->isValidDomain($domain) ) {
            throw new \InnerServe\PostfixAPI\Exception\DomainNotFoundException($domain);
        }

        if ( !$this->mailboxExists($local_part, $domain) ) {
            throw new \InnerServe\PostfixAPI\Exception\MailboxDoesNotExistException($local_part, $domain);
        }

        $stmt = $this->pdo->prepare("DELETE FROM mailbox WHERE local_part = :local_part AND domain = :domain");

        $stmt->execute(array(
            'local_part' => $local_part,
            'domain' => $domain,
        ));

        $stmt = $this->pdo->prepare("DELETE FROM alias WHERE address = :address");

        $stmt->execute(array(
            'address' => $local_part . '@' . $domain
        ));

        return true;

    }

	/**
	 * Creates a mailbox on the given domain
	 * @param  string $username Username of the mailbox
	 * @param  string $password Plain text password
	 * @param  string $domain   Domain name for the new mailbox
	 * @param  string $name     Full name of user
	 * @param  integer $quota   Quota for the mailbox, in megabytes
	 * @return boolean          Boolean value if it was successful or not
	 */
	public function createMailbox($username, $password, $domain, $name, $quota=100) {
		if ( !$this->isValidDomain($domain) ) {
			throw new \InnerServe\PostfixAPI\Exception\DomainNotFoundException($domain);
		}

		if ( $this->mailboxExists($username, $domain) ) {
			throw new \InnerServe\PostfixAPI\Exception\MailboxExistsException($username, $domain);
		}

		if ( empty($username) ) {
			throw new \InnerServe\PostfixAPI\Exception\MissingRequiredParameterException('Username');	
		}		

		if ( empty($password) ) {
			throw new \InnerServe\PostfixAPI\Exception\MissingRequiredParameterException('Password');	
		}		

		if ( empty($domain) ) {
			throw new \InnerServe\PostfixAPI\Exception\MissingRequiredParameterException('Domain');	
		}		

		if ( empty($name) ) {
			throw new \InnerServe\PostfixAPI\Exception\MissingRequiredParameterException('Name');	
		}		

		if ( empty($quota) || !is_numeric($quota) ) {
			throw new \InnerServe\PostfixAPI\Exception\MissingRequiredParameterException('Quota');	
		}		

		$domain_stats = $this->getDomainInfo($domain);

		if ( ($domain_stats['actual_quota']+$quota) > $domain_stats['maxquota'] ) {
			throw new \InnerServe\PostfixAPI\Exception\DomainMailboxSizeExceededException();
		}

		if ( $domain_stats['actual_mailboxes'] >= $domain_stats['mailboxes'] ) {
			throw new \InnerServe\PostfixAPI\Exception\DomainMailboxLimitExceededException();
		}
		
		$stmt = $this->pdo->prepare("INSERT INTO 
			mailbox (username, password, name, maildir, quota, local_part, domain, created, modified, active)
			VALUES
			(:username, :password, :name, :maildir, :quota, :local_part, :domain, :created, :modified, 1)");

		$stmt->execute(array(
			'username' => $username . "@" . $domain,
			'password' => $this->pacrypt($password),
			'name' => $name,
			'maildir' => $domain . "/" . $username . "/",
			'quota' => intval($quota) * 1048576,
			'local_part' => $username,
			'domain' => $domain,
			'created' => date("Y-m-d H:i:s"),
			'modified' => date("Y-m-d H:i:s"),
			));

        $stmt = $this->pdo->prepare("INSERT INTO 
			alias (address, goto, domain, created, modified, active)
			VALUES
			(:username, :username, :domain, :created, :modified, 1)");

        $stmt->execute(array(
            'username' => $username . "@" . $domain,
            'domain' => $domain,
            'created' => date("Y-m-d H:i:s"),
            'modified' => date("Y-m-d H:i:s"),
        ));

		return true;

	}


	/**
	 * update a mailbox on the given domain
	 * @param  string $username Username of the mailbox
	 * @param  string $password Plain text password
	 * @param  string $domain   Domain name for the new mailbox
	 * @param  string $name     Full name of user
	 * @param  integer $quota   Quota for the mailbox, in megabytes
	 * @return boolean          Boolean value if it was successful or not
	 */
	public function updateMailbox($username, $password, $domain, $name, $quota) {
		if ( !$this->isValidDomain($domain) ) {
			throw new \InnerServe\PostfixAPI\Exception\DomainNotFoundException($domain);
		}

		if ( !$this->mailboxExists($username, $domain) ) {
			throw new \InnerServe\PostfixAPI\Exception\MailboxNotFoundException($username, $domain);
		}

		if ( empty($username) ) {
			throw new \InnerServe\PostfixAPI\Exception\MissingRequiredParameterException('Username');
		}

//		if ( empty($password) ) {
//			throw new \InnerServe\PostfixAPI\Exception\MissingRequiredParameterException('Password');
//		}

		if ( empty($domain) ) {
			throw new \InnerServe\PostfixAPI\Exception\MissingRequiredParameterException('Domain');
		}

		if ( empty($name) ) {
			throw new \InnerServe\PostfixAPI\Exception\MissingRequiredParameterException('Name');
		}

		if ( empty($quota) || !is_numeric($quota) ) {
			throw new \InnerServe\PostfixAPI\Exception\MissingRequiredParameterException('Quota');
		}

		$domain_stats = $this->getDomainInfo($domain);

		if ( ($domain_stats['actual_quota']+$quota) > $domain_stats['maxquota'] ) {
//			throw new \InnerServe\PostfixAPI\Exception\DomainMailboxSizeExceededException();
		}

		if ( $domain_stats['actual_mailboxes'] > $domain_stats['mailboxes'] ) {
			throw new \InnerServe\PostfixAPI\Exception\DomainMailboxLimitExceededException();
		}

        if ( $password ) {
            $stmt = $this->pdo->prepare(
                "UPDATE mailbox SET
				username = :username,
				password = :password,
				name = :name,
				quota = :quota,
				modified = :modified
				WHERE username = :username AND domain = :domain"
            );

            $stmt->execute(
                array(
                    'username' => $username . "@" . $domain,
                    'password' => $this->pacrypt($password),
                    'name' => $name,
                    'quota' => intval($quota) * 1048576,
                    'domain' => $domain,
                    'modified' => date("Y-m-d H:i:s")
                )
            );
        } else {
            $stmt = $this->pdo->prepare(
                "UPDATE mailbox SET
				username = :username,
				name = :name,
				quota = :quota,
				modified = :modified
				WHERE username = :username AND domain = :domain"
            );

            $stmt->execute(
                array(
                    'username' => $username . "@" . $domain,
                    'name' => $name,
                    'quota' => intval($quota) * 1048576,
                    'domain' => $domain,
                    'modified' => date("Y-m-d H:i:s")
                )
            );
        }

		return $this->getMailBox($username, $domain);

	}

	/**
	 * Get domain information
	 * @param  string $domain Domain to get information for
	 * @return array          array of information
	 */
	public function getDomainInfo($domain) {
		$stmt = $this->pdo->prepare('
			SELECT domain, description, aliases, mailboxes, maxquota, quota, active,
			(SELECT SUM(quota)/1048576 FROM mailbox m WHERE m.domain = d.domain) as actual_quota,
			(SELECT COUNT(*) FROM mailbox m WHERE m.domain = d.domain) as actual_mailboxes,
			(SELECT COUNT(*) FROM alias m WHERE m.domain = d.domain) as actual_aliases
			FROM domain d WHERE domain = :domain');
		$stmt->execute(array('domain' => $domain));

		return $stmt->fetch(\PDO::FETCH_ASSOC);		
	}

	public function mailboxExists($username, $domain) {
		$stmt = $this->pdo->prepare('SELECT COUNT(*) as cnt FROM mailbox WHERE local_part = :local_part AND domain = :domain');
		$stmt->execute(array('local_part' => $username, 'domain' => $domain));

		$result = $stmt->fetch(\PDO::FETCH_ASSOC);
		return ( $result['cnt'] > 0 );		
	}

	public function isValidDomain($domain) {
		$stmt = $this->pdo->prepare('SELECT COUNT(*) as cnt FROM domain WHERE domain = :domain');
		$stmt->execute(array('domain' => $domain));

		$result = $stmt->fetch(\PDO::FETCH_ASSOC);
		return ( $result['cnt'] > 0 );
	}


	private function pacrypt ($pw, $pw_db="")
	{
	    global $CONF;
	    $pw = stripslashes($pw);
	    $password = "";
	    $salt = "";
		
		$CONF['encrypt'] = 'md5crypt';
		
	    if ($CONF['encrypt'] == 'md5crypt') {
	        $split_salt = preg_split ('/\$/', $pw_db);
	        if (isset ($split_salt[2])) {
	            $salt = $split_salt[2];
	        }
	        $password = $this->md5crypt ($pw, $salt);
	    }

	    elseif ($CONF['encrypt'] == 'md5') {
	        $password = md5($pw);
	    }

	    elseif ($CONF['encrypt'] == 'system') {
	        if (preg_match("/\\$1\\$/", $pw_db)) {
	            $split_salt = preg_split ('/\$/', $pw_db);
	            $salt = "\$1\$${split_salt[2]}\$";
	        }
	        else {
	            if (strlen($pw_db) == 0) {
	                $salt = substr (md5 (mt_rand ()), 0, 2);
	            }
	            else {
	                $salt = substr ($pw_db, 0, 2);
	            }
	        }
	        $password = crypt ($pw, $salt);
	    }

	    elseif ($CONF['encrypt'] == 'cleartext') {
	        $password = $pw;
	    }

	    elseif ($CONF['encrypt'] == 'mysql_encrypt')
	    {
	        $pw = ($pw);
	        if ($pw_db!="") {
	            $salt=(substr($pw_db,0,2));
	            $res=db_query("SELECT ENCRYPT('".$pw."','".$salt."');");
	        } else {
	            $res=db_query("SELECT ENCRYPT('".$pw."');");
	        }
	        $l = db_row($res["result"]);
	        $password = $l[0];
	    }

	    elseif ($CONF['encrypt'] == 'authlib') {
	        $flavor = $CONF['authlib_default_flavor'];
	        $salt = substr($this->create_salt(), 0, 2); # courier-authlib supports only two-character salts
	        if(preg_match('/^{.*}/', $pw_db)) {
	            // we have a flavor in the db -> use it instead of default flavor
	            $result = preg_split('/[{}]/', $pw_db, 3); # split at { and/or }
	            $flavor = $result[1];  
	            $salt = substr($result[2], 0, 2);
	        }

	        if(stripos($flavor, 'md5raw') === 0) {
	            $password = '{' . $flavor . '}' . md5($pw);
	        } elseif(stripos($flavor, 'md5') === 0) {
	            $password = '{' . $flavor . '}' . base64_encode(md5($pw, TRUE));
	        } elseif(stripos($flavor, 'crypt') === 0) {
	            $password = '{' . $flavor . '}' . crypt($pw, $salt);
		} elseif(stripos($flavor, 'SHA') === 0) {
		    $password = '{' . $flavor . '}' . base64_encode(sha1($pw, TRUE));
	        } else {
	            die("authlib_default_flavor '" . $flavor . "' unknown. Valid flavors are 'md5raw', 'md5', 'SHA' and 'crypt'");
	        }
	    }

	    elseif (preg_match("/^dovecot:/", $CONF['encrypt'])) {
	        $split_method = preg_split ('/:/', $CONF['encrypt']);
	        $method       = strtoupper($split_method[1]);
	        if (! preg_match("/^[A-Z0-9-]+$/", $method)) { die("invalid dovecot encryption method"); }  # TODO: check against a fixed list?
	        if (strtolower($method) == 'md5-crypt') die("\$CONF['encrypt'] = 'dovecot:md5-crypt' will not work because dovecotpw generates a random salt each time. Please use \$CONF['encrypt'] = 'md5crypt' instead."); 

	        $dovecotpw = "dovecotpw";
	        if (!empty($CONF['dovecotpw'])) $dovecotpw = $CONF['dovecotpw'];

	        # Use proc_open call to avoid safe_mode problems and to prevent showing plain password in process table
	        $spec = array(
	            0 => array("pipe", "r"), // stdin
	            1 => array("pipe", "w"), // stdout
	            2 => array("pipe", "w"), // stderr
	        );

	        $pipe = proc_open("$dovecotpw '-s' $method", $spec, $pipes);

	        if (!$pipe) {
	            die("can't proc_open $dovecotpw");
	        } else {
	            // use dovecot's stdin, it uses getpass() twice
	            // Write pass in pipe stdin
	            fwrite($pipes[0], $pw . "\n", 1+strlen($pw)); usleep(1000);
	            fwrite($pipes[0], $pw . "\n", 1+strlen($pw));
	            fclose($pipes[0]);

	            // Read hash from pipe stdout
	            $password = fread($pipes[1], "200");

	            if ( !preg_match('/^\{' . $method . '\}/', $password)) {
	                $stderr_output = stream_get_contents($pipes[2]);
	                error_log('dovecotpw password encryption failed.');
	                error_log('STDERR output: ' . $stderr_output);
	                die("can't encrypt password with dovecotpw, see error log for details"); 
	            }

	            fclose($pipes[1]);
	            fclose($pipes[2]);
	            proc_close($pipe);

	            $password = trim(str_replace('{' . $method . '}', '', $password));
	        }
	    }

	    else {
	        die ('unknown/invalid $CONF["encrypt"] setting: ' . $CONF['encrypt']);
	    }

	    $password =  ($password);
	    return $password;
	}

	//
	// md5crypt
	// Action: Creates MD5 encrypted password
	// Call: md5crypt (string cleartextpassword)
	//

	private function md5crypt ($pw, $salt="", $magic="")
	{
	    $MAGIC = "$1$";

	    if ($magic == "") $magic = $MAGIC;
	    if ($salt == "") $salt = $this->create_salt ();
	    $slist = explode ("$", $salt);
	    if ($slist[0] == "1") $salt = $slist[1];

	    $salt = substr ($salt, 0, 8);
	    $ctx = $pw . $magic . $salt;
	    $final = hex2bin (md5 ($pw . $salt . $pw));

	    for ($i=strlen ($pw); $i>0; $i-=16)
	    {
	        if ($i > 16)
	        {
	            $ctx .= substr ($final,0,16);
	        }
	        else
	        {
	            $ctx .= substr ($final,0,$i);
	        }
	    }
	    $i = strlen ($pw);

	    while ($i > 0)
	    {
	        if ($i & 1) $ctx .= chr (0);
	        else $ctx .= $pw[0];
	        $i = $i >> 1;
	    }
	    $final = hex2bin (md5 ($ctx));

	    for ($i=0;$i<1000;$i++)
	    {
	        $ctx1 = "";
	        if ($i & 1)
	        {
	            $ctx1 .= $pw;
	        }
	        else
	        {
	            $ctx1 .= substr ($final,0,16);
	        }
	        if ($i % 3) $ctx1 .= $salt;
	        if ($i % 7) $ctx1 .= $pw;
	        if ($i & 1)
	        {
	            $ctx1 .= substr ($final,0,16);
	        }
	        else
	        {
	            $ctx1 .= $pw;
	        }
	        $final = hex2bin (md5 ($ctx1));
	    }
	    $passwd = "";
	    $passwd .= $this->to64 (((ord ($final[0]) << 16) | (ord ($final[6]) << 8) | (ord ($final[12]))), 4);
	    $passwd .= $this->to64 (((ord ($final[1]) << 16) | (ord ($final[7]) << 8) | (ord ($final[13]))), 4);
	    $passwd .= $this->to64 (((ord ($final[2]) << 16) | (ord ($final[8]) << 8) | (ord ($final[14]))), 4);
	    $passwd .= $this->to64 (((ord ($final[3]) << 16) | (ord ($final[9]) << 8) | (ord ($final[15]))), 4);
	    $passwd .= $this->to64 (((ord ($final[4]) << 16) | (ord ($final[10]) << 8) | (ord ($final[5]))), 4);
	    $passwd .= $this->to64 (ord ($final[11]), 2);
	    return "$magic$salt\$$passwd";
	}

	private function create_salt ()
	{
	    srand ((double) microtime ()*1000000);
	    $salt = substr (md5 (rand (0,9999999)), 0, 8);
	    return $salt;
	}

	private function to64 ($v, $n)
	{
	    $ITOA64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	    $ret = "";
	    while (($n - 1) >= 0)
	    {
	        $n--;
	        $ret .= $ITOA64[$v & 0x3f];
	        $v = $v >> 6;
	    }
	    return $ret;
	}
}

if ( !function_exists( 'hex2bin' ) ) {
    function hex2bin( $str ) {
        $sbin = "";
        $len = strlen( $str );
        for ( $i = 0; $i < $len; $i += 2 ) {
            $sbin .= pack( "H*", substr( $str, $i, 2 ) );
        }

        return $sbin;
    }
}
