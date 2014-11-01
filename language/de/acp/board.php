<?php
/**
*
* @package phpBB Extension - ck-ws Auth Shibboleth
* @copyright (c) 2014 Christoph Kreutzer
* @license http://opensource.org/licenses/BSD-2-Clause BSD 2-Clause License
*
*/
if(!defined('IN_PHPBB'))
{
	exit;
}
if(empty($lang) || !is_array($lang))
{
	$lang = array();
}

$lang = array_merge($lang, array(
	'SHIBBOLETH_SETUP_BEFORE_USE' => 'Du musst die Shibboleth-Authentifizierung aktiviert haben, um diese Methode zu aktivieren. Außerdem muss eine Shibboleth-Session aktiv sein (z.B. manuell über < href="/Shibboleth.sso/Login">/Shibboleth.sso/Login</a>), bei der das konfigurierte Benutzerattribut gleich deinem phpBB-Benutzernamen ist.',

	'SHIBBOLETH' => 'Shibboleth',

	'SHIBBOLETH_USER' => 'Benutzerattribut',
	'SHIBBOLETH_USER_EXPLAIN' => 'Das Shibboleth-Attribut, das als Benutzername dient, z.B. <samp>REMOTE_USER</samp> oder <samp>uid</samp>',

	'SHIBBOLETH_HANDLERBASE' => 'Shibboleth SP',
	'SHIBBOLETH_HANDLERBASE_EXPLAIN' => 'Pfad zum Shibboleth SP, Standard: <samp>/Shibboleth.sso/</samp>',

	'SHIBBOLETH_LOGINHANDLER' => 'Shibboleth Login Handler',
	'SHIBBOLETH_LOGINHANDLER_EXPLAIN' => 'Handler des SP, der Logins behandelt, Standard: <samp>Login</samp>, für WAYF: <samp>WAYF/Identifier</samp>',

	'SHIBBOLETH_LOGOUTHANDLER' => 'Shibboleth Logout Handler',
	'SHIBBOLETH_LOGOUTHANDLER_EXPLAIN' => 'Handler des SP, der Logouts behandelt, Standard: <samp>Logout</samp>',
));