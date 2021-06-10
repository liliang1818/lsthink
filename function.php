<?php
function isetcookie($key, $value, $expire = 0, $httponly = false) {
	global $_W;
	require IA_ROOT . DIRECTORY_SEPARATOR . 'config' . DIRECTORY_SEPARATOR . 'config.php';
	$expire = 0 != $expire ? (time() + $expire) : 0;
	$secure = 443 == $_SERVER['SERVER_PORT'] ? 1 : 0;
	return setcookie($configcookie['pre'] . $key, $value, $expire, '/', "", $secure, $httponly);
}
function igetcookie($key) {
	global $_W;
	require IA_ROOT . DIRECTORY_SEPARATOR . 'config' . DIRECTORY_SEPARATOR . 'config.php';
	$key = $configcookie['pre'] . $key;
	if ($_COOKIE[$key]) {
		return $_COOKIE[$key];
	}
}
function iserializer($value) {
	return serialize($value);
}
function iunserializer($value) {
	if (empty($value)) {
		return array();
	}
	if (!is_serialized($value)) {
		return $value;
	}
	if (version_compare(PHP_VERSION, '7.0.0', '>=')) {
		$result = unserialize($value, array('allowed_classes' => false));
	} else {
		if (preg_match('/[oc]:[^:]*\d+:/i', $value)) {
			return array();
		}
		$result = unserialize($value);
	}
	if (false === $result) {
		$temp = preg_replace_callback('!s:(\d+):"(.*?)";!s', function ($matchs) {
			return 's:' . strlen($matchs[2]) . ':"' . $matchs[2] . '";';
		}, $value);
		return unserialize($temp);
	} else {
		return $result;
	}
}
function is_serialized($data, $strict = true) {
	if (!is_string($data)) {
		return false;
	}
	$data = trim($data);
	if ('N;' == $data) {
		return true;
	}
	if (strlen($data) < 4) {
		return false;
	}
	if (':' !== $data[1]) {
		return false;
	}
	if ($strict) {
		$lastc = substr($data, -1);
		if (';' !== $lastc && '}' !== $lastc) {
			return false;
		}
	} else {
		$semicolon = strpos($data, ';');
		$brace = strpos($data, '}');
		if (false === $semicolon && false === $brace) {
			return false;
		}
		if (false !== $semicolon && $semicolon < 3) {
			return false;
		}
		if (false !== $brace && $brace < 4) {
			return false;
		}
	}
	$token = $data[0];
	switch ($token) {
	case 's':
		if ($strict) {
			if ('"' !== substr($data, -2, 1)) {
				return false;
			}
		} elseif (false === strpos($data, '"')) {
			return false;
		}
	case 'a':
		return (bool) preg_match("/^{$token}:[0-9]+:/s", $data);
	case 'O':
		return false;
	case 'b':
	case 'i':
	case 'd':
		$end = $strict ? '$' : '';

		return (bool) preg_match("/^{$token}:[0-9.E-]+;$end/", $data);
	}
	return false;
}
function strexists($string, $find) {
	return !(false === strpos($string, $find));
}
function is_error($data) {
	if (empty($data) || !is_array($data) || !array_key_exists('errno', $data) || (array_key_exists('errno', $data) && 0 == $data['errno'])) {
		return false;
	} else {
		return true;
	}
}
function scriptname() {
	global $_W;
	$_W['script_name'] = basename($_SERVER['SCRIPT_FILENAME']);
	if (basename($_SERVER['SCRIPT_NAME']) === $_W['script_name']) {
		$_W['script_name'] = $_SERVER['SCRIPT_NAME'];
	} else {
		if (basename($_SERVER['PHP_SELF']) === $_W['script_name']) {
			$_W['script_name'] = $_SERVER['PHP_SELF'];
		} else {
			if (isset($_SERVER['ORIG_SCRIPT_NAME']) && basename($_SERVER['ORIG_SCRIPT_NAME']) === $_W['script_name']) {
				$_W['script_name'] = $_SERVER['ORIG_SCRIPT_NAME'];
			} else {
				if (false !== ($pos = strpos($_SERVER['PHP_SELF'], '/' . $scriptName))) {
					$_W['script_name'] = substr($_SERVER['SCRIPT_NAME'], 0, $pos) . '/' . $_W['script_name'];
				} else {
					if (isset($_SERVER['DOCUMENT_ROOT']) && 0 === strpos($_SERVER['SCRIPT_FILENAME'], $_SERVER['DOCUMENT_ROOT'])) {
						$_W['script_name'] = str_replace('\\', '/', str_replace($_SERVER['DOCUMENT_ROOT'], '', $_SERVER['SCRIPT_FILENAME']));
					} else {
						$_W['script_name'] = 'unknown';
					}
				}
			}
		}
	}

	return $_W['script_name'];
}
function getip() {
	static $ip = '';
	if (isset($_SERVER['REMOTE_ADDR'])) {
		$ip = $_SERVER['REMOTE_ADDR'];
	}
	if (isset($_SERVER['HTTP_CDN_SRC_IP'])) {
		$ip = $_SERVER['HTTP_CDN_SRC_IP'];
	} elseif (isset($_SERVER['HTTP_CLIENT_IP'])) {
		$ip = $_SERVER['HTTP_CLIENT_IP'];
	} elseif (isset($_SERVER['HTTP_X_FORWARDED_FOR']) && preg_match_all('#\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}#s', $_SERVER['HTTP_X_FORWARDED_FOR'], $matches)) {
		foreach ($matches[0] as $xip) {
			if (!preg_match('#^(10|172\.16|192\.168)\.#', $xip)) {
				$ip = $xip;
				break;
			}
		}
	}
	if (preg_match('/^([0-9]{1,3}\.){3}[0-9]{1,3}$/', $ip)) {
		return $ip;
	} else {
		return '127.0.0.1';
	}
}
function ihtmlspecialchars($var) {
	if (is_array($var)) {
		foreach ($var as $key => $value) {
			$var[htmlspecialchars($key)] = ihtmlspecialchars($value);
		}
	} else {
		$var = str_replace('&amp;', '&', htmlspecialchars($var, ENT_QUOTES));
	}

	return $var;
}
function safe_gpc_string($value, $default = '') {
	$value = safe_bad_str_replace($value);
	$value = preg_replace('/&((#(\d{3,5}|x[a-fA-F0-9]{4}));)/', '&\\1', $value);

	if (empty($value) && $default != $value) {
		$value = $default;
	}

	return $value;
}
function safe_bad_str_replace($string) {
	if (empty($string)) {
		return '';
	}
	$badstr = array("\0", '%00', '%3C', '%3E', '<?', '<%', '<?php', '{php', '{if', '{loop', '../');
	$newstr = array('_', '_', '&lt;', '&gt;', '_', '_', '_', '_', '_', '_', '.._');
	$string = str_replace($badstr, $newstr, $string);

	return $string;
}
/**
 * 字符串加密
 * @Author   LILIANG
 * @DateTime 2020-10-29T18:53:02+0800
 * @param    [type]                   $string [需要加密的字符串]
 * @param    string                   $key    [密钥]
 * @return   [type]                           [加密后字符串]
 */
function encrypts($string, $key = MODULE_NAME . "_2021") {
	$key = substr(openssl_digest(openssl_digest($key, 'sha1', true), 'sha1', true), 0, 16);
	// openssl_encrypt 加密不同Mcrypt，对秘钥长度要求，超出16加密结果不变
	$data = openssl_encrypt($string, 'AES-128-ECB', $key, OPENSSL_RAW_DATA);
	$encrypted = strtolower(bin2hex($data));
	return $encrypted;
}
/**
 * 字符串解密
 * @Author   LILIANG
 * @DateTime 2020-10-29T18:53:32+0800
 * @param    [type]                   $string [需要解密的字符串]
 * @param    string                   $key    [密钥]
 * @return   [type]                           [解密后字符串]
 */
function decrypts($string, $key = MODULE_NAME . "_2021") {
	$key = substr(openssl_digest(openssl_digest($key, 'sha1', true), 'sha1', true), 0, 16);
	$decrypted = openssl_decrypt(hex2bin($string), 'AES-128-ECB', $key, OPENSSL_RAW_DATA);
	return $decrypted;
}
function ihttp_build_httpbody($url, $post, $extra) {
	$urlset = ihttp_parse_url($url, true);
	if (is_error($urlset)) {
		return $urlset;
	}

	if (!empty($urlset['ip'])) {
		$extra['ip'] = $urlset['ip'];
	}

	$body = '';
	if (!empty($post) && is_array($post)) {
		$filepost = false;
		$boundary = random(40);
		foreach ($post as $name => &$value) {
			if ((is_string($value) && '@' == substr($value, 0, 1)) && file_exists(ltrim($value, '@'))) {
				$filepost = true;
				$file = ltrim($value, '@');

				$body .= "--$boundary\r\n";
				$body .= 'Content-Disposition: form-data; name="' . $name . '"; filename="' . basename($file) . '"; Content-Type: application/octet-stream' . "\r\n\r\n";
				$body .= file_get_contents($file) . "\r\n";
			} else {
				$body .= "--$boundary\r\n";
				$body .= 'Content-Disposition: form-data; name="' . $name . '"' . "\r\n\r\n";
				$body .= $value . "\r\n";
			}
		}
		if (!$filepost) {
			$body = http_build_query($post, '', '&');
		} else {
			$body .= "--$boundary\r\n";
		}
	}

	$method = empty($post) ? 'GET' : 'POST';
	$fdata = "{$method} {$urlset['path']}{$urlset['query']} HTTP/1.1\r\n";
	$fdata .= "Accept: */*\r\n";
	$fdata .= "Accept-Language: zh-cn\r\n";
	if ('POST' == $method) {
		$fdata .= empty($filepost) ? "Content-Type: application/x-www-form-urlencoded\r\n" : "Content-Type: multipart/form-data; boundary=$boundary\r\n";
	}
	$fdata .= "Host: {$urlset['host']}\r\n";
	$fdata .= "User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:9.0.1) Gecko/20100101 Firefox/9.0.1\r\n";
	if (function_exists('gzdecode')) {
		$fdata .= "Accept-Encoding: gzip, deflate\r\n";
	}
	$fdata .= "Connection: close\r\n";
	if (!empty($extra) && is_array($extra)) {
		foreach ($extra as $opt => $value) {
			if (!strexists($opt, 'CURLOPT_')) {
				$fdata .= "{$opt}: {$value}\r\n";
			}
		}
	}
	if ($body) {
		$fdata .= 'Content-Length: ' . strlen($body) . "\r\n\r\n{$body}";
	} else {
		$fdata .= "\r\n";
	}

	return $fdata;
}
function ihttp_request($url, $post = '', $extra = array(), $timeout = 60) {
	if (function_exists('curl_init') && function_exists('curl_exec') && $timeout > 0) {
		$ch = ihttp_build_curl($url, $post, $extra, $timeout);
		if (is_error($ch)) {
			return $ch;
		}
		$data = curl_exec($ch);
		$status = curl_getinfo($ch);
		$errno = curl_errno($ch);
		$error = curl_error($ch);
		curl_close($ch);
		if ($errno || empty($data)) {
			return error($errno, $error);
		} else {
			return ihttp_response_parse($data);
		}
	}
	$urlset = ihttp_parse_url($url, true);
	if (!empty($urlset['ip'])) {
		$urlset['host'] = $urlset['ip'];
	}

	$body = ihttp_build_httpbody($url, $post, $extra);

	if ('https' == $urlset['scheme']) {
		$fp = ihttp_socketopen('ssl://' . $urlset['host'], $urlset['port'], $errno, $error);
	} else {
		$fp = ihttp_socketopen($urlset['host'], $urlset['port'], $errno, $error);
	}
	stream_set_blocking($fp, $timeout > 0 ? true : false);
	stream_set_timeout($fp, ini_get('default_socket_timeout'));
	if (!$fp) {
		return error(1, $error);
	} else {
		fwrite($fp, $body);
		$content = '';
		if ($timeout > 0) {
			while (!feof($fp)) {
				$content .= fgets($fp, 512);
			}
		}
		fclose($fp);

		return ihttp_response_parse($content, true);
	}
}

function ihttp_get($url) {
	return ihttp_request($url);
}

function ihttp_post($url, $data, $headers) {
	if (empty($headers)) {
		$headers = array('Content-Type' => 'application/x-www-form-urlencoded');
	}
	return ihttp_request($url, $data, $headers);
}

function ihttp_multi_request($urls, $posts = array(), $extra = array(), $timeout = 60) {
	if (!is_array($urls)) {
		return error(1, '请使用ihttp_request函数');
	}
	$curl_multi = curl_multi_init();
	$curl_client = $response = array();

	foreach ($urls as $i => $url) {
		if (isset($posts[$i]) && is_array($posts[$i])) {
			$post = $posts[$i];
		} else {
			$post = $posts;
		}
		if (!empty($url)) {
			$curl = ihttp_build_curl($url, $post, $extra, $timeout);
			if (is_error($curl)) {
				continue;
			}
			if (CURLM_OK === curl_multi_add_handle($curl_multi, $curl)) {
				$curl_client[] = $curl;
			}
		}
	}
	if (!empty($curl_client)) {
		$active = null;
		do {
			$mrc = curl_multi_exec($curl_multi, $active);
		} while (CURLM_CALL_MULTI_PERFORM == $mrc);

		while ($active && CURLM_OK == $mrc) {
			do {
				$mrc = curl_multi_exec($curl_multi, $active);
			} while (CURLM_CALL_MULTI_PERFORM == $mrc);
		}
	}

	foreach ($curl_client as $i => $curl) {
		$response[$i] = curl_multi_getcontent($curl);
		curl_multi_remove_handle($curl_multi, $curl);
	}
	curl_multi_close($curl_multi);

	return $response;
}

function ihttp_socketopen($hostname, $port = 80, &$errno, &$errstr, $timeout = 15) {
	$fp = '';
	if (function_exists('fsockopen')) {
		$fp = @fsockopen($hostname, $port, $errno, $errstr, $timeout);
	} elseif (function_exists('pfsockopen')) {
		$fp = @pfsockopen($hostname, $port, $errno, $errstr, $timeout);
	} elseif (function_exists('stream_socket_client')) {
		$fp = @stream_socket_client($hostname . ':' . $port, $errno, $errstr, $timeout);
	}

	return $fp;
}

function ihttp_response_parse($data, $chunked = false) {
	$rlt = array();

	$pos = strpos($data, "\r\n\r\n");
	$split1[0] = substr($data, 0, $pos);
	$split1[1] = substr($data, $pos + 4, strlen($data));

	$split2 = explode("\r\n", $split1[0], 2);
	preg_match('/^(\S+) (\S+) (.*)$/', $split2[0], $matches);
	$rlt['code'] = !empty($matches[2]) ? $matches[2] : 200;
	$rlt['status'] = !empty($matches[3]) ? $matches[3] : 'OK';
	$rlt['responseline'] = !empty($split2[0]) ? $split2[0] : '';
	$header = explode("\r\n", $split2[1]);
	$isgzip = false;
	$ischunk = false;
	foreach ($header as $v) {
		$pos = strpos($v, ':');
		$key = substr($v, 0, $pos);
		$value = trim(substr($v, $pos + 1));
		if (isset($rlt['headers'][$key]) && is_array($rlt['headers'][$key])) {
			$rlt['headers'][$key][] = $value;
		} elseif (!empty($rlt['headers'][$key])) {
			$temp = $rlt['headers'][$key];
			unset($rlt['headers'][$key]);
			$rlt['headers'][$key][] = $temp;
			$rlt['headers'][$key][] = $value;
		} else {
			$rlt['headers'][$key] = $value;
		}
		if (!$isgzip && 'content-encoding' == strtolower($key) && 'gzip' == strtolower($value)) {
			$isgzip = true;
		}
		if (!$ischunk && 'transfer-encoding' == strtolower($key) && 'chunked' == strtolower($value)) {
			$ischunk = true;
		}
	}
	if ($chunked && $ischunk) {
		$rlt['content'] = ihttp_response_parse_unchunk($split1[1]);
	} else {
		$rlt['content'] = $split1[1];
	}
	if ($isgzip && function_exists('gzdecode')) {
		$rlt['content'] = gzdecode($rlt['content']);
	}

	$rlt['meta'] = $data;
	if ('100' == $rlt['code']) {
		return ihttp_response_parse($rlt['content']);
	}

	return $rlt;
}

function ihttp_response_parse_unchunk($str = null) {
	if (!is_string($str) or strlen($str) < 1) {
		return false;
	}
	$eol = "\r\n";
	$add = strlen($eol);
	$tmp = $str;
	$str = '';
	do {
		$tmp = ltrim($tmp);
		$pos = strpos($tmp, $eol);
		if (false === $pos) {
			return false;
		}
		$len = hexdec(substr($tmp, 0, $pos));
		if (!is_numeric($len) or $len < 0) {
			return false;
		}
		$str .= substr($tmp, ($pos + $add), $len);
		$tmp = substr($tmp, ($len + $pos + $add));
		$check = trim($tmp);
	} while (!empty($check));
	unset($tmp);

	return $str;
}

function ihttp_parse_url($url, $set_default_port = false) {
	if (empty($url)) {
		return error(1);
	}
	$urlset = parse_url($url);
	if (!empty($urlset['scheme']) && !in_array($urlset['scheme'], array('http', 'https'))) {
		return error(1, '只能使用 http 及 https 协议');
	}
	if (empty($urlset['path'])) {
		$urlset['path'] = '/';
	}
	if (!empty($urlset['query'])) {
		$urlset['query'] = "?{$urlset['query']}";
	}
	if (strexists($url, 'https://') && !extension_loaded('openssl')) {
		if (!extension_loaded('openssl')) {
			return error(1, '请开启您PHP环境的openssl', '');
		}
	}
	if (empty($urlset['host'])) {
		$current_url = parse_url($GLOBALS['_W']['siteroot']);
		$urlset['host'] = $current_url['host'];
		$urlset['scheme'] = $current_url['scheme'];
		$urlset['path'] = $current_url['path'] . 'web/' . str_replace('./', '', $urlset['path']);
		$urlset['ip'] = '127.0.0.1';
	} elseif (!ihttp_allow_host($urlset['host'])) {
		return error(1, 'host 非法');
	}
	if ($set_default_port && empty($urlset['port'])) {
		$urlset['port'] = 'https' == $urlset['scheme'] ? '443' : '80';
	}
	return $urlset;
}
// function delete_dir_file($dir_name) {
// 	$result = array();
// 	if (is_dir($dir_name)) {
// 		if ($handle = opendir($dir_name)) {
// 			while (false !== ($item = readdir($handle))) {
// 				if ($item != '.' && $item != '..') {
// 					if (is_dir($dir_name . DIRECTORY_SEPARATOR . $item)) {
// 						delete_dir_file($dir_name . DIRECTORY_SEPARATOR . $item);
// 					} else {
// 						unlink($dir_name . DIRECTORY_SEPARATOR . $item);
// 					}
// 				}
// 			}
// 			closedir($handle);
// 			if (rmdir($dir_name)) {
// 				$result = true;
// 			}
// 		}
// 	}
// 	return $result;
// }
function delete_dir_file($path) {
	$result = array();
	if (substr($path, -1) != DIRECTORY_SEPARATOR) {
		$path = $path . DIRECTORY_SEPARATOR;
	}
	if (is_dir($path)) {
		$p = scandir($path);
		foreach ($p as $val) {
			if ($val != "." && $val != "..") {
				if (is_dir($path . $val)) {
					$nresult = delete_dir_file($path . $val . DIRECTORY_SEPARATOR);
					$result = array_merge($result, $nresult);
					@rmdir($path . $val . DIRECTORY_SEPARATOR);
				} else {
					$result[] = $path . $val;
					@unlink($path . $val);
				}
			}
		}
		@rmdir($path);
	}
	return $result;
}

function get_addons_info_list() {

}
function ihttp_allow_host($host) {
	global $_W;
	if (strexists($host, '@')) {
		return false;
	}
	$pattern = '/^(10|172|192|127)/';
	if (preg_match($pattern, $host) && isset($_W['setting']['ip_white_list'])) {
		$ip_white_list = $_W['setting']['ip_white_list'];
		if ($ip_white_list && isset($ip_white_list[$host]) && !$ip_white_list[$host]['status']) {
			return false;
		}
	}

	return true;
}

function ihttp_build_curl($url, $post, $extra, $timeout) {
	if (!function_exists('curl_init') || !function_exists('curl_exec')) {
		return error(1, 'curl扩展未开启');
	}

	$urlset = ihttp_parse_url($url);
	if (is_error($urlset)) {
		return $urlset;
	}

	if (!empty($urlset['ip'])) {
		$extra['ip'] = $urlset['ip'];
	}

	$ch = curl_init();
	if (!empty($extra['ip'])) {
		$extra['Host'] = $urlset['host'];
		$urlset['host'] = $extra['ip'];
		unset($extra['ip']);
	}
	curl_setopt($ch, CURLOPT_URL, $urlset['scheme'] . '://' . $urlset['host'] . (empty($urlset['port']) || '80' == $urlset['port'] ? '' : ':' . $urlset['port']) . $urlset['path'] . (!empty($urlset['query']) ? $urlset['query'] : ''));
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
	@curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
	curl_setopt($ch, CURLOPT_HEADER, 1);
	@curl_setopt($ch, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
	if ($post) {
		if (is_array($post)) {
			$filepost = false;
			foreach ($post as $name => &$value) {
				if (version_compare(phpversion(), '5.5') >= 0 && is_string($value) && '@' == substr($value, 0, 1)) {
					$post[$name] = new CURLFile(ltrim($value, '@'));
				}
				if ((is_string($value) && '@' == substr($value, 0, 1)) || (class_exists('CURLFile') && $value instanceof CURLFile)) {
					$filepost = true;
				}
			}
			if (!$filepost) {
				$post = http_build_query($post);
			}
		}
		curl_setopt($ch, CURLOPT_POST, 1);
		curl_setopt($ch, CURLOPT_POSTFIELDS, $post);
	}
	if (!empty($GLOBALS['_W']['config']['setting']['proxy'])) {
		$urls = parse_url($GLOBALS['_W']['config']['setting']['proxy']['host']);
		if (!empty($urls['host'])) {
			curl_setopt($ch, CURLOPT_PROXY, "{$urls['host']}:{$urls['port']}");
			$proxytype = 'CURLPROXY_' . strtoupper($urls['scheme']);
			if (!empty($urls['scheme']) && defined($proxytype)) {
				curl_setopt($ch, CURLOPT_PROXYTYPE, constant($proxytype));
			} else {
				curl_setopt($ch, CURLOPT_PROXYTYPE, CURLPROXY_HTTP);
				curl_setopt($ch, CURLOPT_HTTPPROXYTUNNEL, 1);
			}
			if (!empty($GLOBALS['_W']['config']['setting']['proxy']['auth'])) {
				curl_setopt($ch, CURLOPT_PROXYUSERPWD, $GLOBALS['_W']['config']['setting']['proxy']['auth']);
			}
		}
	}
	curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $timeout);
	curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
	curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
	curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
	curl_setopt($ch, CURLOPT_SSLVERSION, 1);
	if (defined('CURL_SSLVERSION_TLSv1')) {
		curl_setopt($ch, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1);
	}
	curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:9.0.1) Gecko/20100101 Firefox/9.0.1');
	if (!empty($extra) && is_array($extra)) {
		$headers = array();
		foreach ($extra as $opt => $value) {
			if (strexists($opt, 'CURLOPT_')) {
				curl_setopt($ch, constant($opt), $value);
			} elseif (is_numeric($opt)) {
				curl_setopt($ch, $opt, $value);
			} else {
				$headers[] = "{$opt}: {$value}";
			}
		}
		if (!empty($headers)) {
			curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
		}
	}

	return $ch;
}
function tablename($name) {
	return config('database.connections.mysql.prefix') . MODULE_NAME . '_' . $name;
}
function settings($name) {
	$setting = settings_get();
	return $setting[$name];
}
function settings_get() {
	global $_W;
	$setting = cache(MODULE_NAME . 'account_settings' . $_W['uniacid']);
	if (empty($setting)) {
		cache(MODULE_NAME . 'account_settings' . $_W['uniacid'], null);
		$settings = think\facade\Db::table('lshd_sys_account_modules')->where('module', '=', MODULE_NAME)->where('uniacid', '=', $_W['uniacid'])->find();
		$setting = iunserializer($settings['settings']);
		cache(MODULE_NAME . 'account_settings' . $_W['uniacid'], $setting);
	}
	return $setting;
}
function wxinfo_get() {
	global $_W;
	$wxinfo = cache(MODULE_NAME . 'account_wxinfo' . $_W['uniacid']);
	if (empty($wxinfo)) {
		cache(MODULE_NAME . 'account_wxinfo' . $_W['uniacid'], null);
		$wxinfos = think\facade\Db::table('lshd_sys_account_modules')->where('module', '=', MODULE_NAME)->where('uniacid', '=', $_W['uniacid'])->find();
		$wxinfo = iunserializer($wxinfos['wxinfo']);
		$wxinfo['flow'] = $wxinfos['flow'];
		cache(MODULE_NAME . 'account_wxinfo' . $_W['uniacid'], $wxinfo);
	}
	return $wxinfo;
}
function tojson($data, $code = 0, $msg = "ok") {
	return json(array('data' => $data, 'code' => $code, 'msg' => $msg));
}
function iset_field($name, $tablename) {
	$fieldlist = think\facade\Db::getFields(tablename($tablename));
	$fieldkeys = array_keys($fieldlist);
	return in_array($name, $fieldkeys);
}
function saveWxinfo($wxinfo) {
	global $_W;
	cache(MODULE_NAME . 'account_wxinfo' . $_W['uniacid'], null);
	$pars = array('module' => MODULE_NAME, 'uniacid' => $_W['uniacid']);
	$row = array();
	$row['wxinfo'] = iserializer($wxinfo);
	if (think\facade\Db::table('lshd_sys_account_modules')->where(array('module' => MODULE_NAME, 'uniacid' => $_W['uniacid']))->column('module')) {
		$result = false !== think\facade\Db::table('lshd_sys_account_modules')->where($pars)->data($row)->update();
	} else {
		$result = false !== think\facade\Db::table('lshd_sys_account_modules')->insert(array('wxinfo' => iserializer($wxinfo), 'module' => MODULE_NAME, 'uniacid' => $_W['uniacid'], 'settings' => iserializer(array()), 'enabled' => 1));
	}
	return $result;
}
function saveSettings($settings) {
	global $_W;
	cache(MODULE_NAME . 'account_settings' . $_W['uniacid'], null);
	$pars = array('module' => MODULE_NAME, 'uniacid' => $_W['uniacid']);
	$row = array();
	$row['settings'] = iserializer($settings);
	if (think\facade\Db::table('lshd_sys_account_modules')->where(array('module' => MODULE_NAME, 'uniacid' => $_W['uniacid']))->column('module')) {
		$result = false !== think\facade\Db::table('lshd_sys_account_modules')->where($pars)->data($row)->update();
	} else {
		$result = false !== think\facade\Db::table('lshd_sys_account_modules')->insert(array('settings' => iserializer($settings), 'module' => MODULE_NAME, 'uniacid' => $_W['uniacid'], 'wxinfo' => iserializer(array()), 'enabled' => 1));
	}
	return $result;
}
function echodata($data) {
	if (is_object($data)) {
		$data = json_encode($data, JSON_FORCE_OBJECT);
	}
	if (is_array($data)) {
		$data = json_encode($data);
	}
	ob_end_clean();
	ob_start();
	if (PHP_OS == 'Windows') {
		echo str_repeat(" ", 4096); //windows
	} else {
		echo str_repeat(' ', 65536); //linux
	}
	header('Cache-Control:no-cache,must-revalidate');
	header('Pragma:no-cache');
	header('Content-Type:application/json; charset=utf-8');
	header("Access-Control-Allow-Origin: *");
	header("Access-Control-Allow-Headers:x-requested-with,content-type");
	echo $data;
	$size = ob_get_length();
	header("Content-Length: " . $size);
	header("Connection: close");
	header("HTTP/1.1 200 OK");
	header('Content-Type:application/json; charset=utf-8');
	ob_end_flush();
	if (ob_get_length()) {
		ob_flush();
	}
	flush();
	if (function_exists("fastcgi_finish_request")) {
		fastcgi_finish_request();
	}
	ignore_user_abort(true);
	set_time_limit(0);
}
function get_real_ip() {
	$ip = '';
	if (!empty($_SERVER["HTTP_CLIENT_IP"])) {
		$ip = $_SERVER["HTTP_CLIENT_IP"];
	}
	if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
		$ips = explode(", ", $_SERVER['HTTP_X_FORWARDED_FOR']);
		if ($ip) {
			array_unshift($ips, $ip);
			$ip = '';
		}
		for ($i = 0; $i < count($ips); $i++) {
			if (!preg_match("/^(10│172.16│192.168)./", $ips[$i])) {
				$ip = $ips[$i];
				break;
			}
		}
	}
	return ($ip ? $ip : $_SERVER['REMOTE_ADDR']);
}
function get_last_time($targetTime) {
	// 今天最大时间
	$todayLast = strtotime(date('Y-m-d 23:59:59'));
	$agoTimeTrue = time() - $targetTime;
	$agoTime = $todayLast - $targetTime;
	$agoDay = floor($agoTime / 86400);
	if ($agoTimeTrue < 60) {
		$result = '刚刚';
	} elseif ($agoTimeTrue < 3600) {
		$result = (ceil($agoTimeTrue / 60)) . '分钟前';
	} elseif ($agoTimeTrue < 3600 * 12) {
		$result = (ceil($agoTimeTrue / 3600)) . '小时前';
	} elseif ($agoDay == 0) {
		$result = '今天 ';
	} elseif ($agoDay == 1) {
		$result = '昨天 ';
	} elseif ($agoDay == 2) {
		$result = '前天 ';
	} elseif ($agoDay > 2 && $agoDay < 30) {
		$result = $agoDay . '天前 ';
	} else {
		$format = date('Y') != date('Y', $targetTime) ? "Y-m-d" : "m-d H:i";
		$result = date($format, $targetTime);
	}
	return $result;
}