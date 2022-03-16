<?php
/**
 * Bootstarp session switcher - directly included
 *
 * @package    BardCanvas
 * @subpackage account_switcher
 * @author     Alejandro Caballero - lava.caballero@gmail.com
 * 
 * @var module $module
 */

use hng2_base\account;
use hng2_base\device;
use hng2_base\module;

if( empty($_GET["switch_to"]) ) return;

$token = three_layer_decrypt(
    $_GET["switch_to"],
    $config->encryption_key,
    $config->website_key,
    md5($config->encryption_key.$config->website_key)
);

if( ! preg_match("/[0-9]+,[0-9]+/", $token) )
{
    send_notification($account->id_account, "error", $module->language->messages->invalid_token);
    
    $uri = parse_url($_SERVER["REQUEST_URI"]);
    header("Location: {$uri["path"]}");
    die("<a href='$url'>{$language->click_here_to_continue}</a>");
}

list($from_id_account, $to_id_account) = explode(",", $token);

$account_ids = array();
$cookie_key  = "{$config->website_key}_ASL";
if( empty($_COOKIE[$cookie_key]) )
{
    send_notification($account->id_account, "error", $module->language->messages->collection_empty);
    
    $uri = parse_url($_SERVER["REQUEST_URI"]);
    header("Location: {$uri["path"]}");
    die("<a href='$url'>{$language->click_here_to_continue}</a>");
}

$account_ids = @unserialize(three_layer_decrypt(
    $_COOKIE[$cookie_key], $cookie_key, $config->encryption_key, md5($config->encryption_key)
));

if( ! is_array($account_ids) )
{
    send_notification($account->id_account, "error", $module->language->messages->collection_reset);
    
    $uri = parse_url($_SERVER["REQUEST_URI"]);
    header("Location: {$uri["path"]}");
    die("<a href='$url'>{$language->click_here_to_continue}</a>");
}

if( ! in_array($to_id_account, $account_ids) )
{
    send_notification($account->id_account, "error", $module->language->messages->account_not_found);
    
    $uri = parse_url($_SERVER["REQUEST_URI"]);
    header("Location: {$uri["path"]}");
    die("<a href='$url'>{$language->click_here_to_continue}</a>");
}

# Remove outstanding session cookies
setcookie( $settings->get("engine.user_online_cookie") , "", 0, "/", $config->cookies_domain );
setcookie( "_" . $config->website_key . "_DIC"         , "", 0, "/", $config->cookies_domain );

# Set new session cookie (it will be opened afterwards)
$cookie_key   = $settings->get("engine.user_session_cookie");
$cookie_val   = encrypt( $to_id_account, $config->encryption_key );
$session_time = time() + (86400 * 30);
setcookie( $cookie_key, $cookie_val, $session_time, "/", $config->cookies_domain );

# Register the login in this device
$to_account = new account($to_id_account);
$device     = new device($to_id_account, get_sanitized_user_agent());
if( ! $device->_exists )
{
    $device->set_new($to_account);
    $device->state = "enabled";
    $device->save();
}
$config->globals["@accounts:account_id_logging_in"] = $to_id_account;
$modules["accounts"]->load_extensions("login", "before_inserting_login_record");
$ip       = get_user_ip();
$host     = @gethostbyaddr($ip); if(empty($host)) $host = $ip;
$location = addslashes(get_geoip_location_with_isp($ip));
$database->exec("
    insert ignore into account_logins set
    `id_account` = '$to_id_account',
    `id_device`  = '$device->id_device',
    `login_date` = '".date("Y-m-d H:i:s")."',
    `ip`         = '$ip',
    `hostname`   = '$host',
    `location`   = '$location'
");

# Reload
$uri = parse_url($_SERVER["REQUEST_URI"]);
header("Location: {$uri["path"]}?account_switched=" . md5(mt_rand(1, 65535)));
die("<a href='$url'>{$language->click_here_to_continue}</a>");
