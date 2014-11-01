<?php
/**
*
* @package phpBB Extension - ck-ws Auth Shibboleth
* @copyright (c) 2014 Christoph Kreutzer
* @license http://opensource.org/licenses/BSD-2-Clause BSD 2-Clause License
*
*/
namespace ckws\authshibboleth\auth\provider;

use phpbb\request\request_interface;

/**
* Shibboleth authentication provider for phpBB 3.1
*/
class shibboleth extends \phpbb\auth\provider\base
{
	/**
	 * phpBB database driver
	 *
	 * @var \phpbb\db\driver\driver_interface
	 */
	protected $db;

	/**
	 * phpBB config
	 *
	 * @var \phpbb\config\config
	 */
	protected $config;

	/**
	 * phpBB request object
	 *
	 * @var \phpbb\request\request
	 */
	protected $request;

	/**
	 * phpBB user object
	 *
	 * @var \phpbb\user
	 */
	protected $user;

	/**
	 * phpBB root path
	 *
	 * @var string
	 */
	protected $phpbb_root_path;

	/**
	 * php file extension
	 *
	 * @var string
	 */
	protected $php_ext;

	/**
	 * auth adapter settings
	 *
	 * @var array
	 */
	protected $settings = array();

	/**
	 * Shibboleth Authentication Constructor
	 *  - called when instance of this class is created
	 *
	 * @param	\phpbb\db\driver\driver_interface	$db					Database object
	 * @param	\phpbb\config\config 				$config				Config object
	 * @param	\phpbb\request\request 				$request			Request object
	 * @param	\phpbb\user 						$user				User object
	 * @param	string 								$phpbb_root_path	Relative path to phpBB root
	 * @param	string 								$php_ext			PHP file extension
	 */
	public function __construct(
		\phpbb\db\driver\driver_interface $db,
		\phpbb\config\config $config,
		\phpbb\request\request $request,
		\phpbb\user $user,
		$phpbb_root_path,
		$php_ext
	)
	{
		$this->db = $db;
		$this->config = $config;
		$this->request = $request;
		$this->user = $user;
		$this->phpbb_root_path = $phpbb_root_path;
		$this->php_ext = $php_ext;

		$this->settings['user'] = (empty($this->config['shibboleth_user_attribute'])) ? 'REMOTE_USER' : $this->config['shibboleth_user_attribute'];
		$this->settings['handler_base'] = (empty($this->config['shibboleth_handler_base'])) ? '/Shibboleth.sso/' : $this->config['shibboleth_handler_base'];
		$this->settings['login_handler'] = (empty($this->config['shibboleth_login_handler'])) ? 'Login' : $this->config['shibboleth_login_handler'];
		$this->settings['logout_handler'] = (empty($this->config['shibboleth_logout_handler'])) ? 'Logout' : $this->config['shibboleth_logout_handler'];
		$this->settings['redirect_after_logout'] = (empty($this->config['shibboleth_redirect_after_logout'])) ? null : $this->config['shibboleth_redirect_after_logout'];


		$this->user->add_lang_ext('ckws/authshibboleth', 'common');
		$this->user->add_lang_ext('ckws/authshibboleth', 'acp/board');
	}

	/**
	 * {@inheritdoc}
	 * - called when authentication method is enabled
	 */
	public function init()
	{
		// check if user is currently authenticated via Shibboleth to prevent lock out
		if(
			!$this->request->is_set($this->settings['user'], request_interface::SERVER)
			|| $this->user->data['username'] !== htmlspecialchars_decode($this->request->server($this->settings['user']))
		)
		{
			return $this->user->lang['SHIBBOLETH_SETUP_BEFORE_USE'];
		}

		return false;
	}

	/**
	 * {@inheritdoc}
	 * - called when login form is submitted
	 */
	public function login($username = null, $password = null)
	{
		// we won't need $username and $passwort, that's all the IdP's thing...

		$shib_user = htmlspecialchars_decode($this->request->server($this->settings['user']));

		// check if Shibboleth user is empty or AUTH_TYPE is not Shibboleth, jump to fallback case (not logged in)
		if(
			!empty($shib_user)
			&& $this->request->server('AUTH_TYPE') === 'Shibboleth'
		)
		{
			$sql = sprintf('SELECT user_id, username, user_password, user_passchg, user_email, user_type FROM %1$s WHERE username = \'%2$s\'', USERS_TABLE, $this->db->sql_escape($shib_user));
			$result = $this->db->sql_query($sql);
			$row = $this->db->sql_fetchrow($result);
			$this->db->sql_freeresult($result);

			// user exists
			if($row)
			{
				// check for inactive users
				if($row['user_type'] == USER_INACTIVE || $row['user_type'] == USER_IGNORE)
				{
					return array(
						'status'	=> LOGIN_ERROR_ACTIVE,
						'error_msg'	=> 'ACTIVE_ERROR',
						'user_row'	=> $row,
					);
				}

				// success
				return array(
					'status'		=> LOGIN_SUCCESS,
					'error_msg'		=> false,
					'user_row'		=> $row,
				);
			}

			// first login, create new user
			return array(
				'status'		=> LOGIN_SUCCESS_CREATE_PROFILE,
				'error_msg'		=> false,
				'user_row'		=> $this->newUserRow($shib_user),
			);
		}

		// Fallback, not logged in
		return array(
			'status'	=> LOGIN_ERROR_EXTERNAL_AUTH,
			'error_msg'	=> 'LOGIN_ERROR_EXTERNAL_AUTH_SHIBBOLETH',
			'user_row'	=> array('user_id' => ANONYMOUS),
		);
	}

	/**
	 * {@inheritdoc}
	 - called when new session is created
	 */
	public function autologin()
	{
		$shib_user = htmlspecialchars_decode($this->request->server($this->settings['user']));

		// check if Shibboleth user is empty or AUTH_TYPE is not Shibboleth, jump to fallback case (not logged in)
		if(
			!empty($shib_user)
			&& $this->request->server('AUTH_TYPE') === 'Shibboleth'
		)
		{
			set_var($shib_user, $shib_user, 'string', true);

			$sql = sprintf('SELECT * FROM %1$s WHERE username = \'%2$s\'', USERS_TABLE, $this->db->sql_escape($shib_user));
			$result = $this->db->sql_query($sql);
			$row = $this->db->sql_fetchrow($result);
			$this->db->sql_freeresult($result);

			// user exists
			if($row)
			{
				// check for inactive users
				if($row['user_type'] == USER_INACTIVE || $row['user_type'] == USER_IGNORE)
				{
					return array();
				}

				// success
				return $row;
			}

			// user does not exist atm, we'll fix that
			if(!function_exists('user_add'))
			{
				include($this->phpbb_root_path . 'includes/functions_user.' . $this->php_ext);
			}

			user_add($this->newUserRow($shib_user));

			// get the newly created user row
			// $sql already defined some lines before
			$result = $this->db->sql_query($sql);
			$row = $this->db->sql_fetchrow($result);
			$this->db->sql_freeresult($result);

			if($row)
			{
				return $row;
			}
		}

		return array();
	}

	/**
	 * {@inheritdoc}
	 * - called on every request when session is active
	 */
	public function validate_session($user)
	{
		// Check if Shibboleth user is set, AUTH_TYPE is Shibboleth and the usernames are the same, then all is fine
		if(
			$this->request->is_set($this->settings['user'], request_interface::SERVER)
			&& $this->request->server('AUTH_TYPE') === 'Shibboleth'
			&& $user['username'] === htmlspecialchars_decode($this->request->server($this->settings['user']))
		)
		{
			return true;
		}

		// if the user is Shibboleth auth'd but first case did not fire, he isn't logged in to phpBB - invalidate his session so autologin() is called ;)
		if($this->request->server('AUTH_TYPE') === 'Shibboleth')
		{
			return false;
		}

		// if the user type is ignore, then it's probably an anonymous user or a bot
		if($user['user_type'] == USER_IGNORE)
		{
			return true;
		}

		// no case matched, shouldn't occur...
		return false;
	}

	/**
	 * {@inheritdoc}
	 * - called when user logs out
	 */
	public function logout($data, $new_session)
	{
		// the SP's login handler
		$shib_sp_url = sprintf('%s%s', $this->settings['handler_base'], $this->settings['logout_handler']);

		redirect($shib_sp_url, false, true);
	}

	/**
	 * {@inheritdoc}
	 * - should return custom configuration options
	 */
	public function acp()
	{
		// these are fields in the config for this auth provider
		return array(
			'shibboleth_user_attribute',
			'shibboleth_handler_base',
			'shibboleth_login_handler',
			'shibboleth_logout_handler',
		);
	}

	/**
	 * {@inheritdoc}
	 * - should return configuration options template
	 */
	public function get_acp_template($new_config)
	{
		return array(
			'TEMPLATE_FILE'	=> '@ckws_authshibboleth/auth_provider_shibboleth.html',
			'TEMPLATE_VARS'	=> array(
				'AUTH_SHIBBOLETH_USER'				=> $new_config['shibboleth_user_attribute'],
				'AUTH_SHIBBOLETH_HANDLERBASE'		=> $new_config['shibboleth_handler_base'],
				'AUTH_SHIBBOLETH_LOGINHANDLER'		=> $new_config['shibboleth_login_handler'],
				'AUTH_SHIBBOLETH_LOGOUTHANDLER'		=> $new_config['shibboleth_logout_handler'],
			),
		);
	}

	/**
	* {@inheritdoc}
	* - should return additional template data for login form
	*/
	public function get_login_data()
	{
		// if user is not authenticated via Shibboleth, we send him to the SP for logging in
		if($this->request->server('AUTH_TYPE') !== 'Shibboleth')
		{
			//page to send back to (forum index)
			$phpbb_url = append_sid(sprintf('%s/%s.%s', generate_board_url(), 'index', $this->php_ext), false, false);
			// the SP's login handler
			$shib_sp_url = sprintf('%s%s?target=%s', $this->settings['handler_base'], $this->settings['login_handler'], urlencode($phpbb_url));

			redirect($shib_sp_url, false, true);
		}

		return array(
			'TEMPLATE_FILE'	=> '@ckws_authshibboleth/login_body_shibboleth.html',
			'VARS'	=> array(
				'LOGINBOX_AUTHENTICATE_SHIBBOLETH' => true,
			),
		);
	}

	/**
	 * This function generates an array which can be passed to the user_add function in order to create a user
	 *
	 * @param 	string	$username 	The username of the new user.
	 * @param 	string	$password 	The password of the new user, may be empty
	 * @return 	array 				Contains data that can be passed directly to the user_add function.
	 */
	private function newUserRow($username)
	{
		// first retrieve default group id
		$sql = sprintf('SELECT group_id FROM %1$s WHERE group_name = \'%2$s\' AND group_type = \'%3$s\'', GROUPS_TABLE, $this->db->sql_escape('REGISTERED'), GROUP_SPECIAL);
		$result = $this->db->sql_query($sql);
		$row = $this->db->sql_fetchrow($result);
		$this->db->sql_freeresult($result);

		if(!$row)
		{
			trigger_error('NO_GROUP');
		}

		// generate user account data
		return array(
			'username'		=> $username,
			'user_password'	=> '',
			'user_email'	=> '',
			'group_id'		=> (int)$row['group_id'],
			'user_type'		=> USER_NORMAL,
			'user_ip'		=> $this->user->ip,
			'user_new'		=> ($this->config['new_member_post_limit']) ? 1 : 0,
		);
	}
}
