<?php
/**
 * Module installation file
 *
 * @package    BardCanvas
 * @subpackage account_switcher
 * @author     Alejandro Caballero - lava.caballero@gmail.com
 *
 * Trailing vars:
 * @var string $module_install_action install, uninstall, enable, disable
 * @var array  $messages
 * @var array  $errors
 * @var module $this_module
 * @var module $current_module
 */

use hng2_base\module;

if( $module_install_action == "install" )
{
    $settings->set("modules:account_switcher.required_level", 240);
    
    return;
}

if( $module_install_action == "uninstall" )
{
    $settings->set("modules:account_switcher.required_level", "");
    
    return;
}
