cfapi
=====

CloudFlare API - Client Library

To use, simply include/require the class and instanciate a new object with your API token and CloudFlare email

<?PHP

require_once('CFAPI.Class.php');
$cf = new CFAPI('TOKEN', 'email@domain.com');

?>
