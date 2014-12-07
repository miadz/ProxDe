<?php
/*
Project Name: ProxDe
Type: Modular [PHP Function]
Creator: Andre S.
Github: CoolApps45

THIS SCRIPT GOES THROUGH THE HEADERS AND CHECKS IF THERE IS A MATCH.
THERE IS NO GUARANTEE THAT THIS WILL DETECT ALL PROXIES, IF THE DETECTION FAILS ON THE PROXY THEN IT HAS THOSE HEADERS HIDDEN.

About Exclusions: Exclusions is basically a IP whitelist. You can either have it coded in or you can use a database of your choice to put in the list of IPs.

Sites using Cloudflare are supported.

At the end of the function, there is an example of how to use the real_ip() function.
*/

if(isset($_SERVER['HTTP_CF_CONNECTING_IP'])) {
// Check if using Cloudflare's service and if so then set client IP superglobal to use Cloudflares.
	$_SERVER['REMOTE_ADDR'] = $_SERVER['HTTP_CF_CONNECTING_IP'];
}
$ip = $_SERVER['REMOTE_ADDR'];

function real_ip($ip) {
	$count = 0;
	$proxy_h = array(
		'HTTP_VIA',
		'VIA',
		'HTTP_FORWARDED_FOR_IP',
		'HTTP_X_FORWARDED_FOR',
		'HTTP_FORWARDED_FOR',
		'HTTP_X_FORWARDED',
		'HTTP_FORWARDED',
		'HTTP_CLIENT_IP',
		'CLIENT_IP',
		'X_FORWARDED_FOR',
		'FORWARDED_FOR',
		'X_FORWARDED',
		'FORWARDED',
		'FORWARDED_FOR_IP',
		'HTTP_PROXY_CONNECTION'
	); // Headers to go through.
	$excl = array(); // IP exclusion "list"
	if(!in_array($ip, $excl)) {
		foreach($proxy_h as $x){
			if(isset($_SERVER[$x]) && $_SERVER[$x] != $ip) {
				$count += 1; // If on proxy
			}
			elseif(!isset($_SERVER[$x]) || $_SERVER[$x] == $ip) {
				$count += 0; // If not detected on proxy
			}
		}
		}
	else {
		$count += 0; // Exclusion
	}
	if($count > 0) {
		return False; // If count variable is more than 0 (proxy hit)
	}
	else {
		return True; // If there was 0 as a result (no proxy detected)
	}
}
echo '- - - - ProxDe - - - -';
echo '<br>';
echo '<br>';
if(real_ip($ip) === False) {
	echo 'A proxy has been detected.'; // This should be obvious..
}
else {
	echo 'You\'ve passed detection.';
}
?>
