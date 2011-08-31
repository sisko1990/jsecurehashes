<?php

/**
 * @version		$Id$
 * @copyright	Copyright (C) 2005 - 2011 Open Source Matters, Inc. All rights reserved.
 * @copyright	Copyright (C) 2011 Jan Erik Zassenhaus. All rights reserved.
 * @license		GNU General Public License version 2 or later; see LICENSE.txt
 */
// No direct access
defined('_JEXEC') or die;

jimport('joomla.plugin.plugin');

/**
 * Joomla secure password hashes authentication plugin
 *
 * @package		Joomla.Plugin
 * @subpackage	Authentication.jsecurehashes
 */
class plgAuthenticationJSecureHashes extends JPlugin
{
    private $user_id = '';
    private $password = '';
    private $hash = '';
    private $param_hashalgorithm = '';
    private $param_emaillogin = '';
    private $available_jhashes = array('ssha', 'sha', 'crypt', 'smd5', 'md5-hex', 'aprmd5', 'md5-base64', 'plain');



    /**
     * This method should handle any authentication and report back to the subject.
     *
     * @access	public
     * @param	array	Array holding the user credentials
     * @param	array	Array of extra options
     * @param	object	Authentication response object
     * @return	boolean
     */
    public function onUserAuthenticate($credentials, $options, &$response)
    {
        jimport('joomla.user.helper');

        $response->type = 'JSecureHashes';
        // Joomla does not like blank passwords
        if (empty($credentials['password']))
        {
            $response->status = JAUTHENTICATE_STATUS_FAILURE;
            $response->error_message = JText::_('JGLOBAL_AUTH_EMPTY_PASS_NOT_ALLOWED');
            return false;
        }

        // Initialise variables.
        $conditions = '';
        $this->param_emaillogin = $this->params->get('emaillogin');
        $this->param_hashalgorithm = $this->params->get('hashalgorithm');
        $this->password = $credentials['password'];

        // Get a database object
        $db = JFactory::getDbo();
        $query = $db->getQuery(true);

        $query->select('id, password');
        $query->from('#__users');
        if ($this->param_emaillogin == '1')
        {
            $query->where('username = ' . $db->Quote($credentials['username']) . ' OR email = ' . $db->Quote($credentials['username']));
        }
        else
        {
            $query->where('username = ' . $db->Quote($credentials['username']));
        }

        $db->setQuery($query);
        $result = $db->loadObject();

        // Save the result for later use
        $this->user_id = $result->id;
        $this->hash = $result->password;

        if ($result)
        {
            switch ($this->param_hashalgorithm)
            {
                // The current algorithm for all users is a Joomla! one
                case in_array($this->param_hashalgorithm, $this->available_jhashes):
                    if ($this->jSecureHashesCheckJoomlaPassword() === true)
                    {
                        $this->jSecureHashesLogin($credentials, $options, $response);
                    }
                    elseif ($this->jSecureHashesCheckDrupalPassword() === true)
                    {
                        $this->jSecureHashesUpdateJoomlaHash();
                        $this->jSecureHashesLogin($credentials, $options, $response);
                    }
                    else
                    {
                        $response->status = JAUTHENTICATE_STATUS_FAILURE;
                        $response->error_message = JText::_('JGLOBAL_AUTH_INVALID_PASS');
                    }
                    break;

                // The current algorithm for all users is a Drupal one
                case 'drupal':
                    if ($this->jSecureHashesCheckDrupalPassword() === true)
                    {
                        $this->jSecureHashesLogin($credentials, $options, $response);
                    }
                    elseif ($this->jSecureHashesCheckJoomlaPassword() === true)
                    {
                        // Update to Drupal hash
                        $this->jSecureHashesUpdateDrupalHash();
                        $this->jSecureHashesLogin($credentials, $options, $response);
                    }
                    else
                    {
                        $response->status = JAUTHENTICATE_STATUS_FAILURE;
                        $response->error_message = JText::_('JGLOBAL_AUTH_INVALID_PASS');
                    }
                    break;

                default:
                    $response->status = JAUTHENTICATE_STATUS_FAILURE;
                    $response->error_message = JText::_('JGLOBAL_AUTH_NO_USER');
                    break;
            }
        }
        else
        {
            $response->status = JAUTHENTICATE_STATUS_FAILURE;
            $response->error_message = JText::_('JGLOBAL_AUTH_NO_USER');
        }
    }



    /**
     * This method checks if we have a valid Joomla! user password. If not return false.
     *
     * @access private
     * @return boolean
     */
    private function jSecureHashesCheckJoomlaPassword()
    {
        // If password has ":" in it, it is a Joomla! password hash
        if ((substr($this->hash, 0, 3) !== '$S$') && (strpos($this->hash, ':') !== false))
        {
            $parts = explode(':', $this->hash);
            $crypt = $parts[0];
            $salt = @$parts[1];
            $testcrypt = JUserHelper::getCryptedPassword($this->password, $salt, $this->param_hashalgorithm);

            if ($crypt === $testcrypt)
            {
                return true;
            }
            else
            {
                foreach ($this->available_jhashes as $hashtype)
                {
                    $testcrypt = JUserHelper::getCryptedPassword($this->password, $salt, $hashtype);
                    if ($crypt === $testcrypt)
                    {
                        $this->jSecureHashesUpdateJoomlaHash($this->password, $this->param_hashalgorithm);
                        return true;
                    }
                }
                return false;
            }
        }
        else
        {
            return false;
        }
    }



    /**
     * This method checks if we have a valid Drupal! user password. If not return false.
     *
     * @access private
     * @return boolean false
     */
    private function jSecureHashesCheckDrupalPassword()
    {
        // Check if we have a Drupal hash
        if (substr($this->hash, 0, 3) === '$S$')
        {
            include_once 'libraries/drupal_password_hash.php';

            if (user_check_password($this->password, $this->hash) === true)
            {
                if (user_needs_new_hash($this->hash) === true)
                {
                    $this->jSecureHashesUpdateDrupalHash();
                }
                return true;
            }
            else
            {
                return false;
            }
        }
        else
        {
            return false;
        }
    }



    /**
     * This methode updates the password field in the database with a new Joomla! password hash.
     *
     * @access private
     */
    private function jSecureHashesUpdateJoomlaHash()
    {
        $salt = JUserHelper::genRandomPassword(32);
        $crypt = JUserHelper::getCryptedPassword($this->password, $salt, $this->param_hashalgorithm);
        $newHash = $crypt . ':' . $salt;

        // Get a database object
        $db = JFactory::getDbo();

        $db->setQuery(
            'UPDATE #__users' .
            ' SET password = "' . $newHash . '"' .
            ' WHERE id = ' . $this->user_id
        )->query();
    }



    /**
     * This methode updates the password field in the database with a new Drupal password hash.
     *
     * @access private
     */
    private function jSecureHashesUpdateDrupalHash()
    {
        include_once 'libraries/drupal_password_hash.php';

        $newHash = user_hash_password(trim($this->password));

        // Get a database object
        $db = JFactory::getDbo();

        $db->setQuery(
            'UPDATE #__users' .
            ' SET password = "' . $newHash . '"' .
            ' WHERE id = ' . $this->user_id
        )->query();
    }



    /**
     * This method should handle a successful authentication and report back to the subject.
     *
     * @access	private
     * @param	array	Array holding the user credentials
     * @param	array	Array of extra options
     * @param	object	Authentication response object
     * @return	boolean
     */
    private function jSecureHashesLogin($credentials, $options, &$response)
    {
        $user = JUser::getInstance($this->user_id); // Bring this in line with the rest of the system
        $response->username = $user->username;
        $response->email = $user->email;
        $response->fullname = $user->name;
        if (JFactory::getApplication()->isAdmin())
        {
            $response->language = $user->getParam('admin_language');
        }
        else
        {
            $response->language = $user->getParam('language');
        }
        $response->status = JAUTHENTICATE_STATUS_SUCCESS;
        $response->error_message = '';
    }
}