<?php
/**
 * Credentials validation checker
 * 
 * @package    BardCanvas
 * @subpackage account_switcher
 * @author     Alejandro Caballero - lava.caballero@gmail.com
 * 
 * $_POST args:
 * @param string "user_name"
 * @param string "password"
 */

use hng2_base\account;

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

if( empty($_POST["user_name"]) || empty($_POST["password"]) )
    die( $modules["accounts"]->language->errors->missing_params );

#
# Validate account
#

$xaccount = new account($_POST["user_name"]);
if( $xaccount->id_account == $account->id_account ) die( $current_module->language->messages->no_self_account );
if( ! $xaccount->_exists ) die( $modules["accounts"]->language->errors->account_unexistent );
if( $xaccount->state != "enabled" ) die( $modules["accounts"]->language->errors->account_disabled );
if( md5(trim(stripslashes($_POST["password"]))) != $xaccount->password ) die( $modules["accounts"]->language->errors->wrong_password );

#
# Cookie ops
#

if( in_array($xaccount->id_account, $account_ids) ) die( $current_module->language->messages->already_in );

#
# Return the token for redirection
#

$token = urlencode(three_layer_encrypt(
    $account->id_account . "," . $xaccount->id_account,
    $config->encryption_key,
    $config->website_key,
    md5($config->encryption_key.$config->website_key)
));

$uri  = parse_url($_SERVER["HTTP_REFERER"]);
$link = "{$uri["path"]}?switch_to={$token}";

$account_ids[] = $account->id_account;
$account_ids[] = $xaccount->id_account;
$account_ids   = array_unique($account_ids);
$cookie_val    = three_layer_encrypt( serialize($account_ids), $cookie_key, $config->encryption_key, md5($config->encryption_key) );
setcookie( $cookie_key, $cookie_val, time() + (86400 * 365), "/", $config->cookies_domain );

if( $failed_dec ) send_notification(
    $account->id_account, "warning", $current_module->language->messages->collection_reset
);

echo "OK:$link";
