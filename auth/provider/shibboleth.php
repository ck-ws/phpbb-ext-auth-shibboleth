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
use phpbb\auth\provider\base as baseProvider;

/**
* Shibboleth authentication provider for phpBB 3.1
*/
class shibboleth extends baseProvider
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
	 * phpBB passwords manager
	 *
	 * @var \phpbb\passwords\manager
	 */
	protected $passwords_manager;

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
	 *
	 * @param	\phpbb\db\driver\driver_interface	$db					Database object
	 * @param	\phpbb\config\config 				$config				Config object
	 * @param	\phpbb\passwords\manager			$passwords_manager	Passwords Manager object
	 * @param	\phpbb\request\request 				$request			Request object
	 * @param	\phpbb\user 						$user				User object
	 * @param	string 								$phpbb_root_path	Relative path to phpBB root
	 * @param	string 								$php_ext			PHP file extension
	 */
	public function __construct(
		\phpbb\db\driver\driver_interface $db,
		\phpbb\config\config $config,
		\phpbb\passwords\manager $passwords_manager,
		\phpbb\request\request $request,
		\phpbb\user $user,
		$phpbb_root_path,
		$php_ext
	)
	{
		$this->db = $db;
		$this->config = $config;
		$this->passwords_manager = $passwords_manager;
		$this->request = $request;
		$this->user = $user;
		$this->phpbb_root_path = $phpbb_root_path;
		$this->php_ext = $php_ext;

		$this->settings['user'] = (empty($this->config['shibboleth_user_attribute'])) ? 'REMOTE_USER' : $this->config['shibboleth_user_attribute'];
		$this->settings['handlerBase'] = '/Shibboleth.sso/';
		$this->settings['loginHandler'] = 'Login';
		$this->settings['logoutHandler'] = 'Logout';
	}

	/**
	 * {@inheritdoc}
	 */
	public function init()
	{
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
			$sql = 'SELECT user_id, username, user_password, user_passchg, user_email, user_type
					FROM ' . USERS_TABLE . "
					WHERE username = '" . $this->db->sql_escape($shib_user) . "'";
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

			$sql = 'SELECT *
					FROM ' . USERS_TABLE . "
					WHERE username = '" . $this->db->sql_escape($shib_user) . "'";
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
	 */
	public function validate_session($user)
	{
		// Check if Shibboleth user is set, AUTH_TYPE is Shibboleth and the usernames are the same, then all is fine
		if(
			$this->request->is_set($this->settings['user'], request_interface::SERVER)
			&& $this->request->server('AUTH_TYPE') === 'Shibboleth'
			&& $user['username'] === $this->request->server($this->settings['user'])
		)
		{
			return true;
		}

		// if the user type is ignore, then it's probably an anonymous user or a bot
		if($user['user_type'] == USER_IGNORE)
		{
			return true;
		}

		// no case matched, drop this
		return false;
	}

	/**
	 * {@inheritdoc}
	 */
	public function acp()
	{
		// These are required fields in the config table
		return array(
			'shibboleth_user_attribute',
		);
	}

	/**
	 * {@inheritdoc}
	 */
	public function get_acp_template($new_config)
	{
		return array(
			'TEMPLATE_FILE'	=> 'auth_provider_shibboleth.html',
			'TEMPLATE_VARS'	=> array(
				'AUTH_SHIBBOLETH_USER'	=> $new_config['shibboleth_user_attribute'],
			),
		);
	}

	/**
	* {@inheritdoc}
	*/
	public function get_login_data()
	{
		$phpbbUrl = append_sid(generate_board_url() . '/index.' . $this->php_ext, false, false);
		$shibSpUrl = sprintf('%s%s?target=%s', $this->settings['handlerBase'], $this->settings['loginHandler'], urlencode($phpbbUrl));

		return array(
			'TEMPLATE_FILE'	=> 'login_body_shibboleth.html',
			'TEMPLATE_VARS'	=> array(
				'U_AUTH_SHIBBOLETH'	=> redirect($shibSpUrl, true, true),
			),
		);
	}

	/**
	 * This function generates an array which can be passed to the user_add function in order to create a user
	 *
	 * @param 	string	$username 	The username of the new user.
	 * @return 	array 				Contains data that can be passed directly to the user_add function.
	 */
	private function newUserRow($username)
	{
		// first retrieve default group id
		$sql = 'SELECT group_id
				FROM ' . GROUPS_TABLE . "
				WHERE group_name = '" . $this->db->sql_escape('REGISTERED') . "' AND group_type = '" . GROUP_SPECIAL . "'";
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
			'user_password'	=> $this->passwords_manager->hash(''),
			'user_email'	=> '',
			'group_id'		=> (int)$row['group_id'],
			'user_type'		=> USER_NORMAL,
			'user_ip'		=> $this->user->ip,
			'user_new'		=> ($this->config['new_member_post_limit']) ? 1 : 0,
		);
	}
}
