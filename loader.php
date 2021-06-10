<?php
require __DIR__ . DIRECTORY_SEPARATOR . 'defind.php';
require __DIR__ . DIRECTORY_SEPARATOR . 'dload.php';
require __DIR__ . DIRECTORY_SEPARATOR . 'function.php';
define('IA_ROOT', str_replace('\\', '/', dirname(dirname(__FILE__))));
define('JULI', IA_ROOT . DIRECTORY_SEPARATOR . 'runtime' . DIRECTORY_SEPARATOR . 'jsondate' . DIRECTORY_SEPARATOR);
define('LS_IOS', "0");
define('LS_SYSOS_TYPES', '');
define('MAGIC_QUOTES_GPC', (function_exists('get_magic_quotes_gpc') && @get_magic_quotes_gpc()) || @ini_get('magic_quotes_sybase'));
define('ADDONS_PLUGIN_URL', 'http://addons.ls11.cn/');
$_W = $_GPC = array();
if (strpos($_SERVER["REQUEST_URI"], MODULE_NAME) !== false) {
	define('SYS_TYPE', 'W7');
} else {
	define('SYS_TYPE', '');
}
$_W['SYS_TYPE'] = SYS_TYPE;
if (SYS_TYPE) {
	// 微擎系统
	if (!empty($_GPC['i'])) {
		$_W['uniacid'] = $_GPC['i'];
	}
	if (empty($_W['uniacid'])) {
		$_W['uniacid'] = igetcookie('__uniacid');
	}
	$_W['uniacid'] = intval($_W['uniacid']);
	define('THEME_URL', "../../../static/");
	define('ADDONS_THEME_URL', "../../../../static/");
	define('SPATH', "addons/" . MODULE_NAME . "/public");
	define('SURL', "/addons/" . MODULE_NAME . "/public/");
	define('PLUGINURL', "addons/" . MODULE_NAME . "/public");
} else {
	// 独立系统
	define('STYPES', "wxapp");
	define('THEME_URL', "../../static/");
	define('ADDONS_THEME_URL', "../../../static/");
	define('SPATH', "");
	define('SURL', "/");
	define('PLUGINURL', "");
}
$_W['ishttps'] = isset($_SERVER['SERVER_PORT']) && 443 == $_SERVER['SERVER_PORT'] ||
isset($_SERVER['HTTP_FROM_HTTPS']) && 'on' == strtolower($_SERVER['HTTP_FROM_HTTPS']) ||
(isset($_SERVER['HTTPS']) && 'off' != strtolower($_SERVER['HTTPS'])) ||
isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && 'https' == strtolower($_SERVER['HTTP_X_FORWARDED_PROTO']) ||
isset($_SERVER['HTTP_X_CLIENT_SCHEME']) && 'https' == strtolower($_SERVER['HTTP_X_CLIENT_SCHEME']) ? true : false;
$_W['sitescheme'] = $_W['ishttps'] ? 'https://' : 'http://';
$_W['script_name'] = htmlspecialchars(scriptname());
$sitepath = substr($_SERVER['PHP_SELF'], 0, strrpos($_SERVER['PHP_SELF'], '/'));
$_W['host'] = isset($_SERVER['HTTP_X_FORWARDED_HOST']) ? $_SERVER['HTTP_X_FORWARDED_HOST'] : (isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : (isset($_SERVER['SERVER_NAME']) ? $_SERVER['SERVER_NAME'] : ''));
$_W['siteroot'] = htmlspecialchars($_W['sitescheme'] . $_W['host']);
if (MAGIC_QUOTES_GPC) {
	$_GET = istripslashes($_GET);
	$_POST = istripslashes($_POST);
	$_COOKIE = istripslashes($_COOKIE);
}
foreach ($_GET as $key => $value) {
	if (is_string($value) && !is_numeric($value)) {
		$value = safe_gpc_string($value);
	}
	$_GET[$key] = $_GPC[$key] = $value;
}

$_GPC = array_merge($_GPC, $_POST);
$_GPC = ihtmlspecialchars($_GPC);
define('ATTACHMENT_ROOT', IA_ROOT . DIRECTORY_SEPARATOR . 'public' . DIRECTORY_SEPARATOR . 'attachment' . DIRECTORY_SEPARATOR);
$_W['uniacid'] = 1;