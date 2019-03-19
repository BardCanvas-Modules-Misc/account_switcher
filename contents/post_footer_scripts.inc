<?php
/**
 * Post-footer scripts
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
?>

<!-- Account switcher scripts and dialogs -->

<script type="text/javascript">
    
    var account_switcher_removal_prompt         = '<?= addslashes($this_module->language->messages->account_removal_prompt) ?>';
    var account_switcher_addition_dialog_loaded = false;
    var account_switcher_remover_url            = '<?= $this_module->get_url() ?>/scripts/remove_account.php';
    var account_switcher_removed_ok             = '<?= addslashes($this_module->language->messages->account_successfully_removed) ?>';
    
    function account_switcher_add_account()
    {
        if( ! account_switcher_addition_dialog_loaded ) load_account_switcher_addition_dialog();
        
        $('#account_switcher_form')[0].reset();
        $('#account_switcher_dialog').dialog('open');
    }
    
    function remove_switcher_account(trigger, id_account)
    {
        if( ! confirm(account_switcher_removal_prompt) ) return false;
        
        var $target = $(trigger).closest('.main_menu_item');
        $.blockUI(blockUI_default_params);
        var url = sprintf( '%s?id_account=%s&wasuuup=%s', account_switcher_remover_url, id_account, wasuuup() );
        $.get(url, function(response) {
            if( response !== 'OK' )
            {
                throw_notification(response, 'warning');
                $.unblockUI();
                
                return;
            }
            
            $.unblockUI();
            $target.remove();
            throw_notification(account_switcher_removed_ok, 'success');
        });
    }
    
    function load_account_switcher_addition_dialog()
    {
        var $dialog        = $('#account_switcher_dialog');
        var submit_caption = $dialog.attr('data-ok-caption');
        var cancel_caption = $dialog.attr('data-cancel-caption');
        
        $dialog.dialog({
            modal:    true,
            autoOpen: false,
            buttons:  [
                {
                    text:  cancel_caption,
                    icons: { primary: "ui-icon-cancel" },
                    click: function() { $(this).dialog( "close" ); }
                },
                {
                    text: submit_caption,
                    icons: { primary: "ui-icon-check" },
                    click: function() { $('#account_switcher_form').submit(); }
                }
            ]
        });
        
        $('#account_switcher_form').ajaxForm({
            target:       '#account_switcher_target',
            beforeSubmit: function(formData, $form, options) {
                stop_notifications_getter();
                $form.closest('.ui-dialog').block(blockUI_medium_params);
            },
            success: function(responseText, statusText, xhr, $form) {
                if( responseText.indexOf('OK:') < 0 )
                {
                    alert(responseText);
                    $form.closest('.ui-dialog').unblock();
                    start_notifications_getter();
                    
                    return;
                }
                
                setTimeout(function() { location.href = responseText.replace('OK:', ''); }, 1000);
            }
        });
        
        account_switcher_addition_dialog_loaded = true;
    }
    
</script>

<div id="account_switcher_dialog" style="display: none"
     title="<?= $this_module->language->dialog_title ?>"
     data-ok-caption="<?= $language->submit ?>"
     data-cancel-caption="<?= $language->cancel ?>">
    
    <div id="account_switcher_target" style="display: none"></div>
    
    <p><?= $this_module->language->dialog_info ?></p>
    
    <form method="post" id="account_switcher_form"
          action="<?= $this_module->get_url() ?>/scripts/validate_credentials.php">
        
        <div class="field">
            <div class="caption">
                <?= $this_module->language->user_name ?>
            </div>
            <div class="input">
                <input type="text" name="user_name">
            </div>
        </div>
        
        <div class="field">
            <div class="caption">
                <?= $this_module->language->password ?>
            </div>
            <div class="input">
                <input type="password" name="password">
            </div>
        </div>
        
    </form>
    
</div>
