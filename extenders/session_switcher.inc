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
$session_time = time() + (86400*7);
setcookie( $cookie_key, $cookie_val, $session_time, "/", $config->cookies_domain );

# Reload
$uri = parse_url($_SERVER["REQUEST_URI"]);
header("Location: {$uri["path"]}?account_switched=" . md5(mt_rand(1, 65535)));
die("<a href='$url'>{$language->click_here_to_continue}</a>");
