<?php
/**
 * Account removal
 * 
 * @package    BardCanvas
 * @subpackage account_switcher
 * @author     Alejandro Caballero - lava.caballero@gmail.com
 * 
 * $_GET args:
 * @param int "id_account"
 */

include "../../config.php";
include "../../includes/bootstrap.inc";
if( ! $modules["account_switcher"] ) throw_fake_501();
if( ! $modules["account_switcher"]->enabled ) throw_fake_501();

header("Content-Type: text/html; charset=utf-8");

#
# Pre-validations
#

if( ! $account->_exists ) throw_fake_401();
if( $account->state != "enabled" ) throw_fake_401();

$failed_dec  = false;
$account_ids = array();
$cookie_key  = "{$config->website_key}_ASL";
if( ! empty($_COOKIE[$cookie_key]) )
{
    $account_ids = unserialize(three_layer_decrypt(
        $_COOKIE[$cookie_key], $cookie_key, $config->encryption_key, md5($config->encryption_key)
    ));
    if( $account_ids === false )
    {
        $failed_dec  = true;
        $account_ids = array();
    }
}

$level = $settings->get("modules:account_switcher.required_level"); if( empty($level) ) $level = 240;
if( ! in_array($account->id_account, $account_ids) )
    if( $account->level < $level && ! $account->has_admin_rights_to_module("account_switcher") )
        throw_fake_401();

if( empty($_GET["id_account"]) ) die( $current_module->language->messages->invalid_account_id );
if( ! is_numeric($_GET["id_account"]) ) die( $current_module->language->messages->invalid_account_id );
if( $account->id_account == $_GET["id_account"] ) die( $current_module->language->messages->cannot_remove_self );

# Removal

$final_ids = array();
foreach($account_ids as $id_account) if( $id_account != $_GET["id_account"] ) $final_ids[] = $id_account;
$account_ids = array_unique($final_ids);
$cookie_val  = three_layer_encrypt( serialize($account_ids), $cookie_key, $config->encryption_key, md5($config->encryption_key) );
setcookie( $cookie_key, $cookie_val, time() + (86400 * 365), "/", $config->cookies_domain );

if( $failed_dec ) send_notification(
    $account->id_account, "warning", $current_module->language->messages->collection_reset
);

echo "OK";
