<?php
/**
 * @copyright Copyright (C) 2005 - 2013 Open Source Matters, Inc. All rights reserved.
 * @copyright Copyright (C) 2013 Jan Erik Zassenhaus. All rights reserved.
 * @license   GNU General Public License version 2 or later; see LICENSE.txt
 */
// No direct access
defined('_JEXEC') or die;

class JFormFieldJshSystemPlugin extends JFormField
{
    protected $type = 'jshsystemplugin';

    /**
     * Method to get the field input markup.
     *
     * @return  string  The field input markup.
     *
     * @since   11.1
     */
    protected function getInput()
    {
        $pluginType = 'system';
        $pluginName = 'jsecurehashes';

        if (JPluginHelper::isEnabled($pluginType, $pluginName))
        {
            // Plug-in is installed and enabled
            return
                '<div style="border: 1px solid #a6ca8a; border-radius: 5px; background: #e9ffd9; padding: 8px; float: left; font-weight: bold;">'
                . JTEXT::_('PLG_SYSTEM_JSECUREHASHES_ENABLED') . '</div>';
        }
        else
        {
            // Plug-in is disabled or not installed

            // Check if plug-in is installed on filesystem
            if (JFile::exists(JPATH_PLUGINS . '/' . $pluginType . '/' . $pluginName . '/' . $pluginName . '.xml'))
            {
                // Plug-in is installed, but disabled
                return
                    '<div style="border: 1px solid #f5aca6; border-radius: 5px; background: #ffecec; padding: 8px; float: left; font-weight: bold;">'
                    . JTEXT::_('PLG_SYSTEM_JSECUREHASHES_DISABLED') . '</div>';
            }
            else
            {
                // Plug-in isn't installed
                return
                    '<div style="border: 1px solid #f5aca6; border-radius: 5px; background: #ffecec; padding: 8px; float: left; font-weight: bold;">'
                    . JTEXT::_('PLG_SYSTEM_JSECUREHASHES_NOT_INSTALLED') . '</div>';
            }
        }
    }
}