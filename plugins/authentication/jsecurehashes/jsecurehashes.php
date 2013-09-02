<?php

/**
 * @copyright Copyright (C) 2005 - 2013 Open Source Matters, Inc. All rights reserved.
 * @copyright Copyright (C) 2011 Jan Erik Zassenhaus. All rights reserved.
 * @license   GNU General Public License version 2 or later; see LICENSE.txt
 */
// No direct access
defined('_JEXEC') or die;

jimport('joomla.plugin.plugin');

/**
 * Joomla secure password hashes authentication plugin
 *
 * @package    Joomla.Plugin
 * @subpackage Authentication.jsecurehashes
 */
class plgAuthenticationJSecureHashes extends JPlugin
{

    /**
     * This method should handle any authentication and report back to the subject.
     *
     * @access public
     *
     * @param array  Array holding the user credentials
     * @param array  Array of extra options
     * @param object Authentication response object
     *
     * @return boolean
     */
    public function onUserAuthenticate($credentials, $options, &$response)
    {
        jimport('joomla.user.helper');

        $response->type = 'JSecureHashes';
        // Joomla does not like blank passwords
        if (empty($credentials['password']))
        {
            $response->status        = JAuthentication::STATUS_FAILURE;
            $response->error_message = JText::_('JGLOBAL_AUTH_EMPTY_PASS_NOT_ALLOWED');

            return false;
        }

        // Get params from the system plugin
        $jSecureHashesSystemPlugin       = JPluginHelper::getPlugin('system', 'jsecurehashes');
        $jSecureHashesSystemPluginParams = new JRegistry($jSecureHashesSystemPlugin->params);

        // Initialise variables
        $param_hashalgorithm     = $jSecureHashesSystemPluginParams->get('hashalgorithm', 'md5-hex');
        $param_alternativeLogin  = $jSecureHashesSystemPluginParams->get('alternative_login', 'username_only');
        $param_force_cs_username = (int) $jSecureHashesSystemPluginParams->get('force_username_login_cs', '0');

        // Get a database object
        $db    = JFactory::getDbo();
        $query = $db->getQuery(true);

        // Prepare the SQL query
        $query->select($db->quoteName(array('id', 'username', 'password')));
        $query->from($db->quoteName('#__users'));

        if ($param_alternativeLogin === 'username_and_email')
        {
            $query->where(array(
                $db->quoteName('username') . ' = ' . $db->quote($credentials['username']),
                $db->quoteName('email') . ' = ' . $db->quote($credentials['username'])
            ), 'OR');
        }
        elseif ($param_alternativeLogin === 'email_only')
        {
            $query->where($db->quoteName('email') . ' = ' . $db->quote($credentials['username']));
        }
        else
        {
            $query->where($db->quoteName('username') . ' = ' . $db->quote($credentials['username']));
        }

        // Get the results from database
        $db->setQuery($query);
        $result = $db->loadObject();

        // Should we check for upper and lower case in username?
        if (($param_force_cs_username === 1) && (!is_null($result)))
        {
            // Test if username is exactly the same, otherwise it is an error
            if ($result->username !== $credentials['username'])
            {
                $result = null;
            }
        }

        if ($result)
        {
            // Check if we can use our own library
            if (jimport('jsecurehashes.password.hashing'))
            {
                $jsecurehasheslib = new JSecureHashesPasswordHashing();
                $jsecurehasheslib->setDefaultHashAlgorithm($param_hashalgorithm);

                try
                {
                    if ($jsecurehasheslib->checkPasswordWithStoredHash($result->password, $credentials['password'],
                            (int) $result->id) === true)
                    {
                        $user               = JUser::getInstance($result->id);
                        $response->email    = $user->email;
                        $response->fullname = $user->name;

                        if (JFactory::getApplication()->isAdmin())
                        {
                            $response->language = $user->getParam('admin_language');
                        }
                        else
                        {
                            $response->language = $user->getParam('language');
                        }
                        $response->status        = JAuthentication::STATUS_SUCCESS;
                        $response->error_message = '';
                    }
                }
                catch (Exception $exc)
                {
                    $response->status        = JAuthentication::STATUS_FAILURE;
                    $response->error_message = JText::_($exc->getMessage());
                }
            }
            else
            {
                // The user has deleted the library, we use the Joomla! standard authentication procedure as an emergency plan
                $parts     = explode(':', $result->password);
                $crypt     = $parts[0];
                $salt      = @$parts[1];
                $testcrypt = JUserHelper::getCryptedPassword($credentials['password'], $salt);

                if ($crypt == $testcrypt)
                {
                    $user               = JUser::getInstance($result->id); // Bring this in line with the rest of the system
                    $response->email    = $user->email;
                    $response->fullname = $user->name;

                    if (JFactory::getApplication()->isAdmin())
                    {
                        $response->language = $user->getParam('admin_language');
                    }
                    else
                    {
                        $response->language = $user->getParam('language');
                    }
                    $response->status        = JAuthentication::STATUS_SUCCESS;
                    $response->error_message = '';
                }
                else
                {
                    $response->status        = JAuthentication::STATUS_FAILURE;
                    $response->error_message = JText::_('JGLOBAL_AUTH_INVALID_PASS');
                }
            }
        }
        else
        {
            $response->status        = JAuthentication::STATUS_FAILURE;
            $response->error_message = JText::_('JGLOBAL_AUTH_NO_USER');
        }
    }
}