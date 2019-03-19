<?php
/**
 * User menu commands
 *
 * @package    BardCanvas
 * @subpackage account_switcher
 * @author     Alejandro Caballero - lava.caballero@gmail.com
 *
 * @var account  $account
 * @var settings $settings
 * @var config   $config
 * @var template $template
 */

use hng2_base\account;
use hng2_base\account_record;
use hng2_base\accounts_repository;
use hng2_base\config;
use hng2_base\settings;
use hng2_base\template;

global $account, $settings;

if( ! $account->_exists ) return;
if( $account->state != "enabled" ) return;

$account_ids = array();
$cookie_key  = "{$config->website_key}_ASL";
if( ! empty($_COOKIE[$cookie_key]) )
{
    $account_ids = unserialize(three_layer_decrypt(
        $_COOKIE[$cookie_key], $cookie_key, $config->encryption_key, md5($config->encryption_key)
    ));
    if( $account_ids === false ) $account_ids = array();
}

if( empty($account_ids) )
{
    $level = $settings->get("modules:account_switcher.required_level");
    if( empty($level) ) $level = 240;
    if( $account->level < $level && ! $account->has_admin_rights_to_module("account_switcher") ) return;
}
else
{
    if( ! in_array($account->id_account, $account_ids) ) return;
}

/** @var account_record[] $accounts */
$accounts = array();
if( ! empty($account_ids) )
{
    $repository = new accounts_repository();
    $accounts   = $repository->get_multiple($account_ids);
}

if( count($account_ids) == 0 ): ?>
    
    <hr>
    
    <span class="main_menu_item pseudo_link"
          onclick="account_switcher_add_account()">
        <i class="fa fa-exchange fa-fw"></i>
        <?= $this_module->language->switch_account ?>
    </span>
    
<? else: ?>
    
    <hr>
    
    <? foreach($accounts as $xaccount):
        
        if( $xaccount->id_account == $account->id_account ) continue;
        
        $token = urlencode(three_layer_encrypt(
            $account->id_account . "," . $xaccount->id_account,
            $config->encryption_key,
            $config->website_key,
            md5($config->encryption_key.$config->website_key)
        ));
        
        $uri  = parse_url($_SERVER["REQUEST_URI"]);
        $link = "{$uri["path"]}?switch_to={$token}";
        ?>
        
        <a class="main_menu_item clearfix nowrap">
            <span class="pull-right" style="vertical-align: top; padding-left: 10px;">
                <i class="fa fa-trash fa-border" style="cursor: pointer; vertical-align: top;"
                   onclick="return remove_switcher_account(this, '<?= $xaccount->id_account ?>');"></i>
            </span>
            <span onclick="location.href = '<?= $link ?>'" style="cursor: pointer">
                <img src="<?= $xaccount->get_avatar_url() ?>"
                     style="width: 20px; height: 20px; vertical-align: top;">
                <span style="display: inline-block; vertical-align: top; max-width: 200px; overflow: hidden; text-overflow: ellipsis;">
                    <?= replace_escaped_objects($this_module->language->switch_to,
                        array('{$display_name}' => convert_emojis($xaccount->display_name))) ?>
                </span>
            </span>
        </a>
        
    <? endforeach; ?>
    
    <span class="main_menu_item pseudo_link"
          onclick="account_switcher_add_account()">
        <i class="fa fa-plus fa-fw"></i>
        <?= $this_module->language->add_account ?>
    </span>
    
<? endif;
