<?php
/**
 * @copyright Copyright (C) 2005 - 2013 Open Source Matters, Inc. All rights reserved.
 * @copyright Copyright (C) 2013 Jan Erik Zassenhaus. All rights reserved.
 * @license   GNU General Public License version 2 or later; see LICENSE.txt
 */
// No direct access
defined('_JEXEC') or die;

class JFormFieldJshLibrary extends JFormField
{
    protected $type = 'jshlibrary';

    /**
     * Method to get the field input markup.
     *
     * @return  string  The field input markup.
     *
     * @since   11.1
     */
    protected function getInput()
    {

        if (jimport('jsecurehashes.password.hashing') && jimport('jsecurehashes.lib.drupal_password_hash'))
        {
            // Library files are installed
            return
                '<div style="border: 1px solid #a6ca8a; border-radius: 5px; background: #e9ffd9; padding: 8px; float: left; font-weight: bold;">'
                . JText::_('PLG_SYSTEM_JSECUREHASHES_INSTALLED') . '</div>';
        }
        else
        {
            // Library files aren't installed
            return
                '<div style="border: 1px solid #f5aca6; border-radius: 5px; background: #ffecec; padding: 8px; float: left; font-weight: bold;">'
                . JText::_('PLG_SYSTEM_JSECUREHASHES_NOT_INSTALLED') . '</div>';
        }
    }
}