<?php

/**
 * CloudFlare Client API - Client Library
 * @author https://github.com/usefulz
 * Legacy Bug-fixes: Sean Fleming <smenus@me.com>
 */
 
class CFAPI
{

  /**
   * API Endpoint for CloudFlare Client API
   * @access public
   * @var string
   */

  var $url = 'https://www.cloudflare.com/api_json.html';

  /**
   * CloudFlare API Token
   * @see https://www.cloudflare.com/my-account
   * @access protected
   * @var string
   */

  protected $tkn = '';

  /**
   * CloudFlare Email Address
   * @see https://www.cloudflare.com/my-account
   * @access protected
   * @var string
   */

  protected $email = '';

  /**
   * Zone data array
   * @access public
   * @var array
   */

  public $zones = array();

  /**
   * Recent IP array
   * @access public
   * @var array
   */

  public $ips = array();

  /**
   * Associative array of CloudFlare setting abbreviations to their long descriptions
   * @access public
   * @var array
   */

  public $_settings_map = array(
    'dev_mode' => 'Development Mode Status',
    'ob' => 'Always Online Status',
    'ch_ttl' => 'Challenge TTL',
    'exp_ttl' => 'Expire TTL',
    'sec_lvl' => 'Basic Security Level',
    'cache_lvl' => 'Caching Level',
    'async' => 'Rocket Loader Status',
    'minify' => 'Minify Status',
    'ipv46' => 'IPv6 Status',
    'bic' => 'Browser Integrity Check',
    'email_filter' => 'Email Obfuscation',
    'sse' => 'Server-side Excludes',
    'hotlink' => 'Hotlink Protection',
    'geoloc' => 'IP Geolocation',
    'spdy' => 'SPDY Support',
    'ssl' => 'SSL Status',
    'lazy' => 'Mirage2 Lazy Loader',
    'img' => 'Mirage2 Image Resizer',
    'preload' => 'Preloader',
    'waf_profile' => 'Web Application Firewall'
  );

  /**
   * Constructor function
   * @param string $tkn
   * @param string $email
   * @param bool $auto_populate
   */

  public function __construct($tkn, $email, $auto_populate = TRUE)
  {

    $this->url      = 'https://www.cloudflare.com/api_json.html';
    $this->agent    = 'CFAPI-Client 1.2';
    $this->tkn      = ($tkn ? $tkn : FALSE);
    $this->email    = ($email ? $email : FALSE);

    $cache_file = './' . sha1($this->email.'_'.$this->tkn) . '.json';
    $cache_expiry = 600;

    if (file_exists($cache_file))
    {
      $cache_timer = time() - filemtime($cache_file);
      $secs_left = ($cache_expiry - $cache_timer);
    } else {
      $secs_left = -1;
    }

    /**
     * If the cache timer hasn't expired yet..
     */

    if ($secs_left > 0)
    {
      echo "Time remaining until next update: ". $secs_left . " seconds\n";
      $result = json_decode(readfile($cache_file), TRUE);
      if ($result === NULL) die(json_last_error());
      return (array) $result;
    } else {

      /**
       * If the timer is past the expiration, and $auto_populate is enabled
       */

      if ($auto_populate === TRUE)
      {

        /**
         * Load all zones from CloudFlare, and map their zone id's to the zones array
         */

        self::zone_load_multi();
        self::zone_check($this->zones);

        /**
         * Loop through each zone, and grab:
         *  Settings
         *  Stats
         *  DNS Records
         *  Most recent visitor IPs
         */

        foreach($this->zones as $zone => $info)
        {
          $this->zone_settings($zone);
          $this->stats($zone);
          $this->rec_load_all($zone);
          $this->zone_ips($zone);
        }

        /**
         * Save the object as a file in JSON format
         */

        $contents = json_encode($this, JSON_FORCE_OBJECT);
        $fp = fopen($cache_file, 'w');
        fwrite($fp, $contents);
        fclose($fp);

        /**
         * Update the file modification date to reset the timer
         */

        touch($cache_file, time());
        return (array) $this;
      }

    }
  }
  
  /**
   * Grab an array of all zones on current CloudFlare account
   * @return array
   */

  public function zone_load_multi()
  {
    $filter['a'] = 'zone_load_multi';
    $result = $this->APIQuery($filter);

    foreach($result['response']['zones']['objs'] as $obj => $detail)
    {
      $this->zones[ $detail['zone_name'] ] = (array) $obj; 
    }

    return $this->zones;
  }

  /**
   * Get zone details
   * @param string $domain
   * @param string $key    optional
   * @param string $subkey optional
   * @return array
   */

  public function get_zone_detail($domain, $key = NULL, $subkey = NULL)
  {

    if (!array_key_exists($domain, $this->zones))
      throw new Exception('Data for zone $domain not available.');
    if (!array_key_exists($key, $this->zones[$domain]))
      throw new Exception('Key $key for zone $domain not available.');
    if ($subkey !== NULL && !array_key_exists($subkey, $this->zones[$domain][$key]))
      throw new Exception('Subkey $subkey of Key $key for zone $domain not available.');

    if ($key === NULL && $subkey === NULL)
      return (array) $this->zones[$domain];
    if (array_key_exists($key, $this->zones[$domain]) && $subkey === NULL)
      return (array) $this->zones[$domain][$key];
    if (array_key_exists($subkey, $this->zones[$domain][$key]) && $subkey !== NULL)
      return (array) $this->zones[$domain][$key][$subkey];

  }

  /**
   * Grab an array of all zones on current CloudFlare account
   * @param string $zones Can be comma-separated list of zones
   * @return array
   */

  public function zone_check($zones)
  {
    $filter['a']     = 'zone_check';
    $filter['zones']     = implode(',', array_keys($zones));
    $result = $this->APIQuery($filter);

    foreach($result['response']['zones'] as $zone => $detail)
    {
      $this->zones[$zone]['id'] = (int) $detail;
    }

    return (array) $this->zones;
  }

  /**
   * Grab a list of recent IP addresses visiting a CloudFlare enabled site
   * @param string $domain
   * @param int $hours (default: 24)
   * @param string $class r|s|t (Regular, Crawler, Threat)
   * @param int $geo (Set to 1 to add lat/lng to response)
   * @return array
   */

  public function zone_ips($domain, $hours = 24, $class = 'r', $geo = 1)
  {

    if ($hours > 48 || $hours < 1)
    {
      throw new Exception('zone_ips: $hours must be integer between 1 and 48.');
    }

    if (!preg_match('/r|s|t/', $class))
    {
      throw new Exception('zone_ips: $class must be either "r" (Regular), "s" (Crawler), or "t" (Threat).');
    }

    $filter = array(
      'a'     => 'zone_ips',
      'z'     => $domain,
      'hours' => ($hours < 1 ? 24 : $hours),
      'class' => (isset($class) && $class != 'r' ? 'r' : $class),
      'geo'   => (isset($geo) && $geo != 1 ? $geo : 1)
    );

    $result = $this->APIQuery($filter);

    foreach($result['response']['ips'] as $ip => $ip_info)
    {
      $client = $ip_info['ip'];
      $zone   = $ip_info['zone_name'];
      $this->ips[$zone][$client] = $ip_info;
    }

    return (array) $this->ips;
  }

  /**
   * Grab zone settings for a specified zone
   * @param string $domain
   * @return array
   */

  public function zone_settings($domain)
  {

    $filter = array(
      'a' => 'zone_settings',
      'z' => $domain
    );
    $result = $this->APIQuery($filter);

    foreach($result['response']['result']['objs'] as $obj => $settings)
    {
      foreach($settings as $field => $data)
      {
        $this->zones[$domain]['attributes'][$field] = $data;
      }
    }

    return (array) $this->zones;

  }

  /**
   * Grabs stats from a domain
   * @param string $domain
   * @param int $interval
   *   - 20 - Past 30 days
   *   - 30 - Past 7 days
   *   - 40 - Past day
   *   PRO:
   *   - 100 - 24 hours ago
   *   - 110 - 12 hours ago
   *   - 120 - 6 hours ago
   * @return array
   */

  public function stats($domain, $interval = 40)
  {

    $filter = array(
      'a' => 'stats',
      'z' => $domain,
      'interval' => $interval
    );

    $result = $this->APIQuery($filter);

    $begin = $result['response']['result']['timeZero'];
    $end   = $result['response']['result']['timeEnd'];

    /**
     * Calculate total uniques, pageviews, bandwidth, and requests
     */

    foreach($result['response']['result']['objs'] as $obj)
    {

      $_uniques = array_sum(array(
        (int) $obj['trafficBreakdown']['uniques']['regular'],
        (int) $obj['trafficBreakdown']['uniques']['threat'],
        (int) $obj['trafficBreakdown']['uniques']['crawler']
      ));

      $_views = array_sum(array(
        (int) $obj['trafficBreakdown']['pageviews']['regular'],
        (int) $obj['trafficBreakdown']['pageviews']['threat'],
        (int) $obj['trafficBreakdown']['pageviews']['crawler'],
      ));

      $_bandwidth = array_sum(array(
        (float) $obj['bandwidthServed']['cloudflare'],
        (float) $obj['bandwidthServed']['user']
      ));

      $_requests = array_sum(array(
        (int) $obj['requestsServed']['cloudflare'],
        (int) $obj['requestsServed']['user']
      ));

      $this->zones[$domain]['stats']['uniques'] = (int) $_uniques;
      $this->zones[$domain]['stats']['pageviews'] = (int) $_views;
      $this->zones[$domain]['stats']['bandwidth'] = (float) $_bandwidth;
      $this->zones[$domain]['stats']['requests'] = (int) $_requests;

    }

    return (array) $this->zones;

  }

  /**
   * Grab DNS records from given domain
   * @param string $domain
   * @return array
   */

  public function rec_load_all($domain)
  {

    $filter = array(
      'a' => 'rec_load_all',
      'z' => $domain
    );
    $result = $this->APIQuery($filter);

    foreach($result['response']['recs']['objs'] as $rec => $val)
    {
      $this->zones[ $domain ]['recs'][ $val['rec_id'] ] = $val;
    }

    return (array) $this->zones;

  }


  /**
   * Check threat score for a given IP address
   * @param string $search_ip
   * @return string
   */

  public function ip_lkup($search_ip)
  {

    $filter = array(
      'a' => 'ip_lkup',
      'ip' => $search_ip
    );
    $result = $this->APIQuery($filter);

    return (string) $result['response'][$search_ip];

  }

  /* Modification Functions */

  /**
   * Set security level of given domain
   * @param string $domain
   * @param string $level
   *   - help = I'm under attack
   *   - high = High
   *   - med - Medium
   *   - low - Low
   *   - eoff - Essentially off
   * @return array
   */

  public function sec_lvl($domain, $level)
  {

    $filter = array(
      'a' => 'sec_lvl',
      'z' => $domain,
      'v' => $level
    );

    return $this->APIQuery($filter);
  }

  /**
   * Set cache level of given domain
   * @param string $domain
   * @param string $cache_level
   *   - agg = Aggressive
   *   - basic = Basic
   * @return array
   */

  public function cache_lvl($domain, $cache_level = 'basic')
  {

    $filter = array(
      'a' => 'cache_lvl',
      'z' => $domain,
      'v' => ($cache_level == 'basic' ? 'basic' : 'agg')
    );

    return $this->APIQuery($filter);
  }

  /**
   * Toggle development mode
   * @param string $domain
   * @param int $toggle
   *   - 1 - on
   *   - 0 - off
   * @return array
   */

  public function devmode($domain, $toggle)
  {

    $filter = array(
      'a' => 'devmode',
      'z' => $domain,
      'v' => $toggle
    );

    return $this->APIQuery($filter);
  }

  /**
   * Clear CloudFlare proxy cache for given domain
   * @param string $domain
   * @return array
   */

  public function fpurge_ts($domain)
  {

    $filter = array(
      'a' => 'fpurge_ts',
      'z' => $domain,
      'v' => 1
    );

    return $this->APIQuery($filter);

  }

  /**
   * Clear CloudFlare proxy cache for given domain
   * @param string $domain
   * @param string $url
   * @return array
   */

  public function zone_file_purge($domain, $url)
  {

    $filter = array(
      'a' => 'zone_file_purge',
      'z' => $domain,
      'url' => $url
    );

    return $this->APIQuery($filter);

  }

  /**
   * Set Rocket Loader
   * @param string $domain
   * @param string 0|a|m
   *   - 0 = off
   *   - a = Automatic
   *   - m = Manual
   * @return array
   */

  public function async($domain, $value = 'a')
  {

    $filter = array(
      'a' => 'async',
      'z' => $domain,
      'v' => $value
    );

    return $this->APIQuery($filter);

  }

  /**
   * Set Minification
   * @param string $domain
   * @param int $value
   *   - 0 = Off
   *   - 1 = Javascript Only
   *   - 2 = CSS Only
   *   - 3 = Javascript + CSS
   *   - 4 = HTML Only
   *   - 5 = Javascript + HTML
   *   - 6 = CSS + HTML
   *   - 7 = CSS + Javascript + HTML
   * @return array
   */

  public function minify($domain, $value = 0)
  {

    $filter = array(
      'a' => 'minify',
      'z' => $domain,
      'v' => $value
    );

    return $this->APIQuery($filter);

  }

  /**
   * Toggle Mirage2 support
   * @param string $domain
   * @param int $value
   *   - 0 = Off
   *   - 1 = On
   * @return array
   */

  public function mirage2($domain, $value = 0)
  {

    $filter = array(
      'a' => 'mirage2',
      'z' => $domain,
      'v' => $value
    );

    return $this->APIQuery($filter);

  }

  /**
   * Whitelist an IP address
   * @param string $ip
   * @return array
   */

  public function wl($ip)
  {

    $filter = array(
      'a' => 'wl',
      'key' => $ip
    );
    
    return $this->APIQuery($filter);

  }

  /**
   * Blacklist an IP address
   * @param string $ip
   * @return array
   */

  public function ban($ip)
  {

    $filter = array(
      'a' => 'ban',
      'key' => $ip
    );

    return $this->APIQuery($filter);

  }

  /**
   * Unlist an IP address
   * @param string $ip
   * @return array
   */

  public function nul($ip)
  {

    $filter = array(
      'a' => 'nul',
      'key' => $ip
    );

    return $this->APIQuery($filter);

  }

  /**
   * Toggle IPv6 Support
   * @param string $domain
   * @param int $toggle - 0 to disable, 3 to enable
   * @return array
   */

  public function ipv46($domain, $toggle)
  {

    $filter = array(
      'a' => 'ipv46',
      'z' => $domain,
      'v' => $toggle
    );

    return $this->APIQuery($filter);

  }

  /**
   * Add a record to a DNS zone
   * @param string $domain
   * @param string $type A|CNAME|MX|TXT|SPF|AAAA|NS|SRV|LOC
   * @param int $dns_id
   * @param string $name
   * @param string $content
   * @param int $prio - Applies to $type == MX
   * @param string $service - Applies to $type == SRV
   * @param string $srvname - Applies to $type == SRV
   * @param int $protocol - Applies to $type == SRV _tcp|_udp|_tls
   * @param int $weight - Applies to $type == SRV
   * @param int $port - Applies to $type == SRV
   * @param string $target - Applies to $type == SRV
   * @return array
   */

  public function rec_new($domain, $type, $name, $content, $ttl = 300, $prio = 0, $service = '', $srvname = '', $protocol = '', $weight = '', $port = '', $target = '')
  {

    $filter = array(
      'a' => 'rec_new',
      'z' => $domain,
      'type' => $type,
      'name' => $name,
      'content' => $content,
      'ttl' => $ttl
    );

    /**
     * Set record priority if record type is MX or SRV
     */

    if(preg_match('/(MX|SRV)/', $type))
    {
      $filter['prio'] = $prio;
    }

    /**
     * Set miscellaneous DNS record attributes if record type is SRV
     */

    if($type == 'SRV')
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

  /**
   * Edit a record from a DNS zone
   * @param string $domain
   * @param string $type A|CNAME|MX|TXT|SPF|AAAA|NS|SRV|LOC
   * @param int $dns_id
   * @param string $name
   * @param string $content
   * @param bool $orange_cloud Status of CloudFlare proxy
   * @param int $prio - Applies to $type == MX
   * @param string $service - Applies to $type == SRV
   * @param string $srvname - Applies to $type == SRV
   * @param int $protocol - Applies to $type == SRV _tcp|_udp|_tls
   * @param int $weight - Applies to $type == SRV
   * @param int $port - Applies to $type == SRV
   * @param string $target - Applies to $type == SRV
   * @return array
   */

  public function rec_edit($domain, $type, $dns_id, $name, $content, $ttl = 300, $orange_cloud = FALSE, $prio = 0, $service = '', $srvname = '', $protocol = '', $weight = '', $port = '', $target = '')
  {

    $service_mode = ($orange_cloud == FALSE ? 0 : 1);

    $filter = array(
      'a' => 'rec_edit',
      'z' => $domain,
      'type' => $type,
      'id' => $dns_id,
      'name' => $name,
      'content' => $content,
      'ttl' => $ttl
    );

    /**
     * If record type is A, AAAA, or CNAME, insert Orange Cloud preference
     */

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

  /**
   *
   * Delete a record from a DNS zone
   * @param string $domain
   * @param int $dns_id
   * @return array
   */

  public function rec_delete($domain, $dns_id)
  {

    $filter = array(
      'a' => 'rec_delete',
      'z' => $domain,
      'id' => $dns_id
    );

    return $this->APIQuery($filter);

  }
  
  /**
   *
   * API Call Function
   * @param array $args
   * @return array
   */
  
  public function APIQuery($args)
  {

    $args['tkn']   = $this->tkn;
    $args['email'] = $this->email;

    $apisess       = curl_init();

    /**
     * Set default properties of our API query
     */

    $_defaults = array(
      CURLOPT_POST => 1,
      CURLOPT_HEADER => 0,
      CURLOPT_VERBOSE => 0,
      CURLOPT_URL => $this->url,
      CURLOPT_SSL_VERIFYPEER => 1,
      CURLOPT_SSL_VERIFYHOST => 1,
      CURLOPT_HTTP_VERSION => '1.0',
      CURLOPT_USERAGENT => $this->agent,
      CURLOPT_FOLLOWLOCATION => 0,
      CURLOPT_FRESH_CONNECT => 1,
      CURLOPT_RETURNTRANSFER => 1,
      CURLOPT_FORBID_REUSE => 1,
      CURLOPT_TIMEOUT => 30,
      CURLOPT_POSTFIELDS => http_build_query($args)
    );

    curl_setopt_array($apisess, $_defaults);

    $response = curl_exec($apisess);

    /**
     *
     * If the response is not in JSON format
     * then close the session and return FALSE 
     *
     */

    if(!$this->isJSON($response))
    {
      curl_close($apisess);
      return FALSE;
    }

    /**
     *
     * Close our session
     * Return the decoded JSON response
     *
     */

    curl_close($apisess);
    $obj = json_decode($response, true);

    /**
     *
     * If the response was JSON, then check the response msg
     * for errors codes that begin with E_ and return the error
     * Otherwise, just return the decoded JSON
     *
     */

    try {
      self::isAPIError($obj);
    } catch(Exception $e)
    {
     die($e->getMessage() . PHP_EOL);
    }

    return $obj;
  }

  /**
   * Verify JSON format
   * @param string $in_str
   * @return bool
   */

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

  /**
   * Determines if the response was an error
   * @param array $response
   * @return bool
   */

  public function isAPIError($response)
  {
    if ($response['result'] !== 'success')
    {
      if (preg_match('/E_UNAUTH/', $response['msg'])) throw new Exception('Authentication could not be completed.');
      if (preg_match('/E_INVLDINPUT/', $response['msg'])) throw new Exception('Your input was invalid.');
      if (preg_match('/E_MAXAPI/', $response['msg'])) throw new Exception('You have exceeded your allowed number of API calls.');
      return TRUE;
    } else {
      return FALSE;
    }
  }

}
?>

