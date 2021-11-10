<?php
function check_ip_reputation($dcs_rest_key = '', $register = '')
{
  if ( !empty($dcs_rest_key) && isset($_SERVER['REMOTE_ADDR']) )
  {
    $ch = curl_init('https://dcs.trized.com/rest/security/check');
    curl_setopt($ch, CURLOPT_TIMEOUT, 30);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER,1);
    curl_setopt($ch, CURLOPT_HTTPAUTH, CURLAUTH_ANY);
    curl_setopt($ch, CURLOPT_HTTPHEADER, array("X-API-KEY: " . $dcs_rest_key));
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode(array('mode' => 'ip', 'ip' => $_SERVER['REMOTE_ADDR'])));
    $api_response_json = curl_exec($ch);
    curl_close($ch);
    if ( isset($api_response_json) && !empty($api_response_json) )
    {
      $reputation_data = json_decode($api_response_json,TRUE);
      if ( isset($reputation_data['status']) && $reputation_data['status'] == TRUE )
      {
        // =====================================================================
        if ( !empty($register) )
        {
          // Register visitor and traffic (optional)
          register_ip_traffic($dcs_rest_key, $_SERVER, $reputation_data);
        }

        if ( $reputation_data['blocked'] > 0 )
        {
          // Block visitors with a bad reputation
          header('HTTP/1.0 403 Forbidden');
          die();
        }
        // =====================================================================
      }
    }
  }
}


function register_ip_traffic($dcs_rest_key = '', $connection_data = '', $reputation_data = '')
{
  if ( !empty($dcs_rest_key) && !empty($connection_data) )
  {
    $json_request_payload['connection_data'] = $connection_data;
    if ( !empty($reputation_data) && isset($reputation_data['blocked']) && $reputation_data['blocked'] > 0 && isset($reputation_data['reason']) )
    {
      $json_request_payload['reputation_data']['blocked'] = $reputation_data['blocked'];
      $json_request_payload['reputation_data']['reason'] = $reputation_data['reason'];
    }
    $ch = curl_init('https://dcs.trized.com/rest/traffic/register');
    curl_setopt($ch, CURLOPT_TIMEOUT, 30);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER,1);
    curl_setopt($ch, CURLOPT_HTTPAUTH, CURLAUTH_ANY);
    curl_setopt($ch, CURLOPT_HTTPHEADER, array("X-API-KEY: " . $dcs_rest_key));
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($json_request_payload));
    curl_exec($ch);
    curl_close($ch);
  }
}


function update_iptables_blacklist($dcs_rest_key = '', $flush_list = '', $debug = '')
{
  if ( !empty($dcs_rest_key) )
  {
    $ch = curl_init('https://dcs.trized.com/rest/security/blacklist');
    curl_setopt($ch, CURLOPT_TIMEOUT, 30);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER,1);
    curl_setopt($ch, CURLOPT_HTTPAUTH, CURLAUTH_ANY);
    curl_setopt($ch, CURLOPT_HTTPHEADER, array("X-API-KEY: " . $dcs_rest_key));
    curl_setopt($ch, CURLOPT_POST, 1);
    $api_json_response = curl_exec($ch);
    curl_close($ch);
    if ( isset($api_json_response) && !empty($api_json_response) )
    {
      $api_response_data = json_decode($api_json_response,TRUE);
      if ( isset($api_response_data['status']) && $api_response_data['status'] == TRUE )
      {
        $check_ipset_list = exec("ipset -N dcs_blacklist iphash 2>&1");
        if ( strpos($check_ipset_list, 'already exists') !== false )
        {
          if ( !empty($flush_list) )
          {
            if ( !empty($debug) ) { echo "Flushing ipset DCS blacklist..\n"; }
            exec("ipset flush dcs_blacklist 2>&1");
          }
        } else {
          if ( !empty($debug) ) { echo "Creating ipset DCS blacklist..\n"; }
          exec("ipset create dcs_blacklist hash:ip hashsize 4096");
        }
        if ( !empty($debug) ) { echo "Checking ipset list for ".count($api_response_data['blacklist'])." bad guys..\n"; }
        foreach ( $api_response_data['blacklist'] as $bad_visitor_ip => $block_reason )
        {
          $check_blacklist = exec("ipset test dcs_blacklist $bad_visitor_ip 2>&1");
          if ( strpos($check_blacklist, 'is NOT in set') !== false )
          {
            if ( !empty($debug) ) { echo "Blocking [$bad_visitor_ip]..\n"; }
            exec("ipset add dcs_blacklist $bad_visitor_ip 2>&1");
          } else {
            if ( !empty($debug) ) { echo "."; }
          }
        }
        $check_iptables_rule = exec("iptables -C INPUT -m set --match-set dcs_blacklist src -j DROP 2>&1");
        if ( strpos($check_iptables_rule, 'Bad rule') !== false )
        {
          if ( !empty($debug) ) { echo "Activating DCS blacklist in iptables..\n"; }
          exec("iptables -I INPUT -m set --match-set dcs_blacklist src -j DROP && iptables -I FORWARD -m set --match-set dcs_blacklist src -j DROP");
        }
      }
    }
  }
}
?>
