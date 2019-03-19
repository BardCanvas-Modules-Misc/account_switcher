<?php
/**
 * Bootstarp session switcher - after loading session checks
 *
 * @package    BardCanvas
 * @subpackage account_switcher
 * @author     Alejandro Caballero - lava.caballero@gmail.com
 * 
 * @var module $module
 */

use hng2_base\module;

if( empty($_GET["account_switched"]) ) return;
if( $account->_exists ) return;

header("Content-Type: text/html; charset=utf-8");
$uri  = parse_url($_SERVER["REQUEST_URI"]);
$link = "{$uri["path"]}?account_switched=" . md5(mt_rand(1, 65535));
?>
<!DOCTYPE HTML>
<html><head>
    <title><?= $module->language->messages->problem_initializing ?></title>
</head><body style="margin: 0; padding: 0; ">
<table cellpadding="0" cellspacing="0" border="0" style="width: 100vw; height: 100vh">
    <tbody><tr><td align="center" valign="middle" style="width: 100vw; height: 100vh">
        <h1><?= $module->language->messages->problem_initializing ?></h1>
        <p><?= $module->language->messages->browser_not_handled_properly ?></p>
        <p><a href="<?= $link ?>"><?= $module->language->messages->click_here_to_retry ?></a></p>
        <p><?= sprintf($module->language->messages->click_to_try_again, $config->full_root_url) ?></p>
    </td></tr></tbody>
</table>
</body></html>
<?
die();
