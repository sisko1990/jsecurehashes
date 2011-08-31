<?php

/**
 * @version		$Id$
 * @copyright	Copyright (C) 2005 - 2011 Open Source Matters, Inc. All rights reserved.
 * @license		GNU General Public License version 2 or later; see LICENSE.txt
 */
// No direct access
defined('_JEXEC') or die;

jimport('joomla.plugin.plugin');

/**
 * Joomla Authentication plugin
 *
 * @package		Joomla.Plugin
 * @subpackage	Authentication.joomla
 * @since 1.5
 */
class plgAuthenticationJSecureHashes extends JPlugin
{
    private $user_id = '';



    /**
     * This method should handle any authentication and report back to the subject
     *
     * @access	public
     * @param	array	Array holding the user credentials
     * @param	array	Array of extra options
     * @param	object	Authentication response object
     * @return	boolean
     * @since 1.5
     */
    function onUserAuthenticate($credentials, $options, &$response)
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
        $param_hashalgorithm = $this->params->get('hashalgorithm');
        $available_jhashes = array('ssha', 'sha', 'crypt', 'smd5', 'md5-hex', 'aprmd5', 'md5-base64', 'plain');

        // Get a database object
        $db = JFactory::getDbo();
        $query = $db->getQuery(true);

        $query->select('id, password');
        $query->from('#__users');
        $query->where('username=' . $db->Quote($credentials['username']));

        $db->setQuery($query);
        $result = $db->loadObject();

        // Save the result for later use
        $this->user_id = $result->id;

        // If password has ":" in it, it is a Joomla! password hash
        if (($result) && (strpos($result->password, ':') !== false))
        {
            $parts = explode(':', $result->password);
            $crypt = $parts[0];
            $salt = @$parts[1];
            $testcrypt = JUserHelper::getCryptedPassword($credentials['password'], $salt, $param_hashalgorithm);

            if ($crypt !== $testcrypt)
            {
                $invalid_auth = true;

                foreach ($available_jhashes as $hashtype)
                {
                    $testcrypt = JUserHelper::getCryptedPassword($credentials['password'], $salt, $hashtype);
                    if (($crypt === $testcrypt) && ($hashtype !== $param_hashalgorithm))
                    {
                        $this->jSecureHashesUpdateHash($this->user_id, $credentials['password'], $param_hashalgorithm);
                        $this->jSecureHashesLogin($credentials, $options, $response);

                        $invalid_auth = false;
                        break;
                    }
                }

                if ($invalid_auth === true)
                {
                    $response->status = JAUTHENTICATE_STATUS_FAILURE;
                    $response->error_message = JText::_('JGLOBAL_AUTH_INVALID_PASS');
                }
            }
            elseif ($crypt === $testcrypt)
            {
                $this->jSecureHashesLogin($credentials, $options, $response);
            }
        }
        else
        {
            $response->status = JAUTHENTICATE_STATUS_FAILURE;
            $response->error_message = JText::_('JGLOBAL_AUTH_NO_USER');
        }
    }



    function jSecureHashesUpdateHash($user_id, $password, $hashtype)
    {
        $salt = JUserHelper::genRandomPassword(32);
        $crypt = JUserHelper::getCryptedPassword($password, $salt, $hashtype);
        $newHash = $crypt . ':' . $salt;

        // Get a database object
        $db = JFactory::getDbo();

        $db->setQuery(
            'UPDATE #__users' .
            ' SET password = "' . $newHash . '"' .
            ' WHERE id = ' . $user_id
        )->query();
    }



    /**
     * This method should handle any authentication and report back to the subject
     *
     * @access	public
     * @param	array	Array holding the user credentials
     * @param	array	Array of extra options
     * @param	object	Authentication response object
     * @return	boolean
     */
    function jSecureHashesLogin($credentials, $options, &$response)
    {
        $user = JUser::getInstance($this->user_id); // Bring this in line with the rest of the system
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

