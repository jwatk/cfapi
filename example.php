<?php
require_once 'CFAPI.Class.php';

$_token = '';
$_email = '';

$cf = new CFAPI($_token, $_email, FALSE);
$cf->zone_load_multi();
$cf->zone_check($cf->zones);

foreach($cf->zones as $zone => $info)
{
  printf("Zone: %s (ID: %d)\n", $zone, $info['id']);
  $cf->rec_load_all($zone);
}

var_dump($cf->zones);
?>
