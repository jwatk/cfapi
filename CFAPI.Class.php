<?php

/**
 * CloudFlare Client API - Client Library
 * Author:  James Watkins <james@viralsec.com>
 * Bug-fixes: Sean Fleming <smenus@me.com>
 */
 
class CFAPI
{

  public $url;
  public $cversion;
  public $tkn;
  public $email;
  
  public function __construct($tkn, $email)
  {
    $this->url      = "https://www.cloudflare.com/api_json.html";
    $this->agent	= 'CFAPI-Client 1.1/' . $_SERVER['HTTP_HOST'];
    $this->tkn      = $tkn;
    $this->email    = $email;
    return TRUE;
  }
  
  /*****
  ACCESS Functions
  *****/
  
  public function stats($domain, $interval = 40)
  {
    $filter['a']        = 'stats';
    $filter['z']        = $domain;
    $filter['interval'] = $interval;
    return $this->APIQuery($filter);
  }
  public function zone_load_multi()
  {
    $filter['a'] = 'zone_load_multi';
    return $this->APIQuery($filter);
  }
  public function rec_load_all($domain)
  {
    $filter['a'] = 'rec_load_all';
    $filter['z'] = $domain;
    return $this->APIQuery($filter);
  }
  public function zone_check($zones)
  {
    $filter['a']     = 'zone_check';
    $filter['zones'] = implode(',', $zones);
    return $this->APIQuery($filter);
  }
  public function zone_ips($domain, $hours = 24, $class = 't', $geo = FALSE)
  {
    $filter['a']     = 'zone_ips';
    $filter['z']     = $domain;
    $filter['hours'] = ($hours > 48 || $hours < 0 ? 24 : $hours);
    if(isset($class))
    {
      $filter['class'] = $class;
    }
    if(isset($geo))
    {
      $filter['geo'] = 1;
    }
    return $this->APIQuery($filter);
  }
  public function ip_lkup($search_ip)
  {
    $filter['a']  = 'ip_lkup';
    $filter['ip'] = $search_ip;
    return $this->APIQuery($filter);
  }
  public function zone_settings($domain)
  {
    $filter['a'] = 'zone_settings';
    $filter['z'] = $domain;
    return $this->APIQuery($filter);
  }
  
  /*****
  MODIFY Functions
  *****/
  
  public function sec_lvl($domain, $level)
  {
    $filter['a'] = 'sec_lvl';
    $filter['z'] = $domain;
    $filter['v'] = $level;
    return $this->APIQuery($filter);
  }
  public function cache_lvl($domain, $cache_level)
  {
    $filter['a'] = 'cache_lvl';
    $filter['z'] = $domain;
    $filter['v'] = $cache_level;
    return $this->APIQuery($filter);
  }
  public function devmode($domain, $toggle)
  {
    $filter['a'] = 'devmode';
    $filter['z'] = $domain;
    $filter['v'] = $toggle;
    return $this->APIQuery($filter);
  }
  public function fpurge_ts($domain)
  {
    $filter['a'] = 'fpurge_ts';
    $filter['z'] = $domain;
    $filter['v'] = 1;
    return $this->APIQuery($filter);
  }
  public function zone_file_purge($domain, $url)
  {
    $filter['a']   = 'zone_file_purge';
    $filter['z']   = $domain;
    $filter['url'] = $url;
    return $this->APIQuery($filter);
  }
  public function zone_grab($zone_id)
  {
    $filter['a']   = 'zone_grab';
    $filter['zid'] = $zone_id;
    return $this->APIQuery($filter);
  }
  public function wl($ip)
  {
    $filter['a']   = 'wl';
    $filter['key'] = $ip;
    return $this->APIQuery($filter);
  }
  public function ban($ip)
  {
    $filter['a']   = 'ban';
    $filter['key'] = $ip;
    return $this->APIQuery($filter);
  }
  public function nul($ip)
  {
    $filter['a']   = 'nul';
    $filter['key'] = $ip;
    return $this->APIQuery($filter);
  }
  public function ipv46($domain, $toggle)
  {
    $filter['a'] = 'ipv46';
    $filter['z'] = $domain;
    $filter['v'] = $toggle;
  }
  public function rec_new($domain, $type, $name, $content, $ttl = 300, $service_mode = 1, $prio = 0, $service = '', $srvname = '', $protocol = '', $weight = '', $port = '', $target = '')
  {
    $filter['a']       = 'rec_new';
    $filter['z']       = $domain;
    $filter['type']    = $type;
    $filter['name']    = $name;
    $filter['content'] = $content;
    $filter['ttl']     = $ttl;
    if(preg_match('/(A|AAAA|CNAME)/', $type))
    {
      $filter['service_mode'] = $service_mode;
    }
    if(preg_match('/(MX|SRV)/', $type))
    {
      $filter['prio'] = $prio;
    }
    if($type = 'SRV')
    {
      $filter['service']  = $service;
      $filter['srvname']  = $srvname;
      $filter['protocol'] = $protocol;
      $filter['weight']   = $weight;
      $filter['port']     = $port;
      $filter['target']   = $target;
    }
    return $this->APIQuery($filter);
  }
  public function rec_edit($domain, $type, $dns_id, $name, $content, $ttl = 300, $service_mode = 1, $prio = 0, $service = '', $srvname = '', $protocol = '', $weight = '', $port = '', $target = '')
  {
    $filter['a']       = 'rec_edit';
    $filter['z']       = $domain;
    $filter['type']    = $type;
    $filter['id']      = $dns_id;
    $filter['name']    = $name;
    $filter['content'] = $content;
    $filter['ttl']     = $ttl;
    if(preg_match('/(A|AAAA|CNAME)/', $type))
    {
      $filter['service_mode'] = $service_mode;
    }
    if(preg_match('/(MX|SRV)/', $type))
    {
      $filter['prio'] = $prio;
    }
    if($type = 'SRV')
    {
      $filter['service']  = $service;
      $filter['srvname']  = $srvname;
      $filter['protocol'] = $protocol;
      $filter['weight']   = $weight;
      $filter['port']     = $port;
      $filter['target']   = $target;
    }
    return $this->APIQuery($filter);
  }
  public function rec_delete($domain, $dns_id)
  {
    $filter['a']  = 'rec_delete';
    $filter['z']  = $domain;
    $filter['id'] = $dns_id;
    return $this->APIQuery($filter);
  }
  
  /*****
  API Call Function
  *****/
  
  public function APIQuery($args)
  {
    // Set required args
    $args['tkn']   = $this->tkn;
    $args['email'] = $this->email;
    $apiurl        = $this->url;
    /* Initialize cURL Session */
    $apisess       = curl_init();
    /* Set generic options */
    curl_setopt($apisess, CURLOPT_URL, $apiurl);
    curl_setopt($apisess, CURLOPT_USERAGENT, $this->agent);
    curl_setopt($apisess, CURLOPT_HEADER, 0);
    curl_setopt($apisess, CURLOPT_FRESH_CONNECT, 1);
    curl_setopt($apisess, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($apisess, CURLOPT_FORBID_REUSE, 1);
    curl_setopt($apisess, CURLOPT_TIMEOUT, 30);
    curl_setopt($apisess, CURLOPT_FOLLOWLOCATION, 0);
    curl_setopt($apisess, CURLOPT_VERBOSE, 0);
    curl_setopt($apisess, CURLOPT_HTTP_VERSION, '1.0');
    /* SSL Options */
    curl_setopt($apisess, CURLOPT_SSL_VERIFYPEER, 1);
    curl_setopt($apisess, CURLOPT_SSL_VERIFYHOST, 1);
    /* POST method options */
    curl_setopt($apisess, CURLOPT_POST, 1);
    curl_setopt($apisess, CURLOPT_POSTFIELDS, http_build_query($args));
    $response = curl_exec($apisess);
    /* Error handling */
    if(!$this->isJSON($response))
    {
      curl_close($apisess);
      return FALSE;
    }
    curl_close($apisess);
    $obj = json_decode($response);
    if(preg_match('/E_(UNAUTH|INVLDINPUT|MAXAPI)/', $obj->{'msg'}))
    {
      return $obj->{'msg'};
    }
    return $obj;
  }
  public function isJSON($in_str)
  {
    try
    {
      $j = json_decode($in_str);
    }
    catch(Exception $e)
    {
      return FALSE;
    }
    return (is_object($j) ? TRUE : FALSE);
  }
}
?>
