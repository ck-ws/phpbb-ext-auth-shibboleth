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
	'LOGIN_ERROR_EXTERNAL_AUTH_SHIBBOLETH' => 'Du konntest nicht mit Shibboleth angemeldet werden.',
	'LOGIN_AUTH_SHIBBOLETH' => 'Mit Shibboleth anmelden',
));