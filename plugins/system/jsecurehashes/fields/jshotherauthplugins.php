<?php
/**
 * @copyright Copyright (C) 2005 - 2013 Open Source Matters, Inc. All rights reserved.
 * @copyright Copyright (C) 2013 Jan Erik Zassenhaus. All rights reserved.
 * @license   GNU General Public License version 2 or later; see LICENSE.txt
 */
// No direct access
defined('_JEXEC') or die;

class JFormFieldJshOtherAuthPlugins extends JFormField
{
    protected $type = 'jshotherauthplugins';

    /**
     * Method to get the field input markup.
     *
     * @return  string  The field input markup.
     *
     * @since   11.1
     */
    protected function getInput()
    {
        $pluginType = 'authentication';

        $allAuthPlugins    = JPluginHelper::getPlugin($pluginType);
        $cleanedPluginList = $allAuthPlugins;

        foreach ($allAuthPlugins as $key => $pluginObject)
        {
            // We didn't need our own plug-in or the Joomla! authentication plug-in
            if ($pluginObject->name == "jsecurehashes" || $pluginObject->name == "joomla")
            {
                unset($cleanedPluginList[$key]);
            }
        }
        $countOtherAuthPlugins = count($cleanedPluginList);

        if (JPluginHelper::isEnabled($pluginType, 'jsecurehashes'))
        {
            // Plug-in is installed and enabled
            if (JPluginHelper::isEnabled($pluginType, 'joomla'))
            {
                // Joomla! authentication plug-in is enabled

                if ($countOtherAuthPlugins > 0)
                {
                    // Other authentication plug-ins are active, too
                    return
                        '<div style="border: 1px solid #f2c779; border-radius: 5px; background: #fff8c4; padding: 8px; float: left; font-weight: bold;">'
                        . JText::_('PLG_SYSTEM_JSECUREHASHES_FIELD_JSHOTHERAUTHPLUGINS_WARNING_JOOMLA_PLUGIN') . ' '
                        . JText::plural('PLG_SYSTEM_JSECUREHASHES_FIELD_JSHOTHERAUTHPLUGINS_WARNING_OTHER_AUTH_PLUGINS', $countOtherAuthPlugins)
                        . '</div>';
                }
                else
                {
                    // No other authentication plug-ins are active
                    return
                        '<div style="border: 1px solid #f2c779; border-radius: 5px; background: #fff8c4; padding: 8px; float: left; font-weight: bold;">'
                        . JText::_('PLG_SYSTEM_JSECUREHASHES_FIELD_JSHOTHERAUTHPLUGINS_WARNING_JOOMLA_PLUGIN') . '</div>';
                }
            }
            else
            {
                // Joomla! authentication plug-in is disabled

                if ($countOtherAuthPlugins > 0)
                {
                    // Other authentication plug-ins are active
                    return
                        '<div style="border: 1px solid #f2c779; border-radius: 5px; background: #fff8c4; padding: 8px; float: left; font-weight: bold;">'
                        . JText::plural('PLG_SYSTEM_JSECUREHASHES_FIELD_JSHOTHERAUTHPLUGINS_WARNING_OTHER_AUTH_PLUGINS', $countOtherAuthPlugins)
                        . '</div>';

                }
                else
                {
                    // No other authentication plug-ins are active
                    return
                        '<div style="border: 1px solid #a6ca8a; border-radius: 5px; background: #e9ffd9; padding: 8px; float: left; font-weight: bold;">'
                        . JText::_('PLG_SYSTEM_JSECUREHASHES_FIELD_JSHOTHERAUTHPLUGINS_NO_WARNINGS') . '</div>';
                }
            }
        }
        else
        {
            // Plug-in is disabled
            return
                '<div style="border: 1px solid #8ed9f6; border-radius: 5px; background: #e3f7fc; padding: 8px; float: left; font-weight: bold;">'
                . JText::_('PLG_SYSTEM_JSECUREHASHES_FIELD_JSHOTHERAUTHPLUGINS_WARNING_ACTIVATE_JSH_AUTH_PLUGIN') . '</div>';
        }


        // Green: All good

        // Notice: JSH Auth Plug-in deactivated: If you want to activate it disable...

        //return '<div style="border: 1px solid #a6ca8a; border-radius: 5px; background: #e9ffd9; padding: 8px; float: left; font-weight: bold;">'
        //             . JTEXT::_('PLG_SYSTEM_JSECUREHASHES_ERROR') . '</div>';
//        $pluginType = 'authentication';
//        $pluginName = 'jsecurehashes';
//
//        if (JPluginHelper::isEnabled($pluginType, $pluginName))
//        {
//            // Plug-in is installed and enabled
//            return
//                '<div style="border: 1px solid #a6ca8a; border-radius: 5px; background: #e9ffd9; padding: 8px; float: left; font-weight: bold;">'
//                . JTEXT::_('PLG_SYSTEM_JSECUREHASHES_ENABLED') . '</div>';
//        }
//        else
//        {
//            // Plug-in is disabled or not installed
//
//            // Check if plug-in is installed on filesystem
//            if (JFile::exists(JPATH_PLUGINS . '/' . $pluginType . '/' . $pluginName . '/' . $pluginName . '.xml'))
//            {
//                // Plug-in is installed, but disabled
//                return
//                    '<div style="border: 1px solid #f5aca6; border-radius: 5px; background: #ffecec; padding: 8px; float: left; font-weight: bold;">'
//                    . JTEXT::_('PLG_SYSTEM_JSECUREHASHES_DISABLED') . '</div>';
//            }
//            else
//            {
//                // Plug-in isn't installed
//                return
//                    '<div style="border: 1px solid #f5aca6; border-radius: 5px; background: #ffecec; padding: 8px; float: left; font-weight: bold;">'
//                    . JTEXT::_('PLG_SYSTEM_JSECUREHASHES_NOT_INSTALLED') . '</div>';
//            }
//        }
    }
}