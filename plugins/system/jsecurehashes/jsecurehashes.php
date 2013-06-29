<?php
/**
 * @copyright Copyright (C) 2005 - 2013 Open Source Matters, Inc. All rights reserved.
 * @copyright Copyright (C) 2013 Jan Erik Zassenhaus. All rights reserved.
 * @license   GNU General Public License version 2 or later; see LICENSE.txt
 */
// No direct access
defined('_JEXEC') or die;

jimport('joomla.plugin.plugin');

class plgSystemJSecureHashes extends JPlugin
{
    /**
     * Constructor
     *
     * @access protected
     *
     * @param  object $subject The object to observe
     * @param  array  $config  An array that holds the plugin configuration
     *
     * @since  1.5
     */
    public function __construct(& $subject, $config)
    {
        parent::__construct($subject, $config);
        $this->loadLanguage();

        // Load JPHANtOM library language
        $lang = JFactory::getLanguage();
        $lang->load('lib_jsecurehashes', JPATH_SITE);
    }


    public function onUserAfterSave($user, $isNew, $result, $errors)
    {
        if (!empty($user['password_clear']))
        {
            // Get the default hash algorithm
            $defaultHashAlgorithm = $this->params->get('hashalgorithm', 'md5-hex');

            try
            {
                jimport('jsecurehashes.password.hashing');
                $jsecurehasheslib = new JSecureHashesPasswordHashing();
                $jsecurehasheslib->setDefaultHashAlgorithm($defaultHashAlgorithm);

                // Generate the new password hash
                $newPasswordHash = $jsecurehasheslib->getHashForPassword($user['password_clear']);

                // Get a database object
                $db    = JFactory::getDbo();
                $query = $db->getQuery(true);

                $query->update($db->quoteName('#__users'));
                $query->set($db->quoteName('password') . ' = ' . $db->quote($newPasswordHash));
                $query->where($db->quoteName('id') . ' = ' . $db->quote($user['id']));

                $db->setQuery($query)->query();
            }
            catch (Exception $exc)
            {
                throw new Exception($exc->getMessage());
            }
        }

        return true;
    }

}