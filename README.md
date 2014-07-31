#CFAPI - CloudFlare API Client Library

##Things you will need
* CloudFlare Email
* CloudFlare API Token

##Usage

This method will simply offer you the object to make calls as you see fit:


  require_once('CFAPI.Class.php');
    
  $cf = new CFAPI('TOKEN', 'email@example.com', FALSE);
    
  $records = $cf->rec_load_all('example.com');


This method will automatically build a tree of your domains (zones) in CloudFlare, and grab Stats, Recent Visitor IPs, DNS Records, and CloudFlare settings per zone.

  require_once('CFAPI.Class.php');

  $cf = new CFAPI('TOKEN', 'email@example.com', TRUE);

  die(var_dump($cf));


Have a look at the included example.php for a more detailed example.
