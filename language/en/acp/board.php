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
	'SHIBBOLETH_SETUP_BEFORE_USE' => 'You have to setup Shibboleth authentication before you switch phpBB to this authentication method. Also, a Shibboleth session needs to be active (e.g. manually via <a href="/Shibboleth.sso/Login">/Shibboleth.sso/Login</a>) and the configured user attribute needs to be the same as your phpBB username.',

	'SHIBBOLETH' => 'Shibboleth',

	'SHIBBOLETH_USER' => 'user attribute',
	'SHIBBOLETH_USER_EXPLAIN' => 'the Shibboleth attribute which contains the username, e.g. <samp>REMOTE_USER</samp> or <samp>uid</samp>',

	'SHIBBOLETH_HANDLERBASE' => 'Shibboleth SP',
	'SHIBBOLETH_HANDLERBASE_EXPLAIN' => 'Path to Shibboleth SP, default: <samp>/Shibboleth.sso/</samp>',

	'SHIBBOLETH_LOGINHANDLER' => 'Shibboleth Login Handler',
	'SHIBBOLETH_LOGINHANDLER_EXPLAIN' => 'Handler of SP which processes logins, default: <samp>Login</samp>, for WAYF: <samp>WAYF/identifier</samp>',

	'SHIBBOLETH_LOGOUTHANDLER' => 'Shibboleth Logout Handler',
	'SHIBBOLETH_LOGOUTHANDLER_EXPLAIN' => 'Handler of SP which processes logouts, default: <samp>Logout</samp>',
));