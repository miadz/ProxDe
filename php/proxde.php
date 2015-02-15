<?php
/*
Project Name: ProxDe
Version: 1.1
Type: Modular [PHP Function]
Creator: Andre S.
Github: CoolApps45

THIS SCRIPT GOES THROUGH THE HEADERS AND CHECKS IF THERE IS A MATCH.
THERE IS NO GUARANTEE THAT THIS WILL DETECT ALL PROXIES, IF THE DETECTION FAILS ON THE PROXY THEN IT HAS THOSE HEADERS HIDDEN.

About Exclusions: Exclusions is basically a IP whitelist. You can either have it coded in or you can use a database of your choice to put in the list of IPs in array / list form.

Sites using Cloudflare are supported.
If your site uses CF, it's highly recommended to whitelist CF's IPs to avoid any issues on certain networks.
The full IP list of Cloudflare's IPs can be found here: https://cloudflare.com/ips
The origin of the potential issue is from the header is 'HTTP_X_FORWARDED_FOR,' this is required for proxy detection so it's recommended to not to delete this header from the array. CF is techically a proxy (in it's own form) so this isn't really a surprise.
You may find that Cloudflare keeps on poping up with different IPs that you'll need to whitelist, it would be appriciated if this could be reported to me so that those IPs will get initially whitelisted. 

At the end of the function, there's a couple of examples of how to use the real_ip() function.
*/



# FUNCTION START
function real_ip($type = 1) {
	if(isset($_SERVER['HTTP_CF_CONNECTING_IP'])) {
		// Check if using Cloudflare's service and if so then set client IP superglobal to use Cloudflares.
		$_SERVER['REMOTE_ADDR'] = $_SERVER['HTTP_CF_CONNECTING_IP'];
	}
	$ip = $_SERVER['REMOTE_ADDR'];
	$count = 0; // Starting point for count
	$excl = array(); // Exclusion list filler
	$ext_m = $ip; // Output if no header matches found
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
	); // Headers to go through (used for detection)
	if(isset($_SERVER['HTTP_CF_CONNECTING_IP'])) {
		$excl_h = array(
		'108.162.236.6',
		'141.101.106.82',
		'141.101.106.70',
		'199.27.128.0',
		'173.245.48.0',
		'103.21.244.0',
		'103.22.200.0',
		'103.31.4.0',
		'141.101.64.0',
		'108.162.192.0',
		'190.93.240.0',
		'188.114.96.0',
		'197.234.240.0',
		'198.41.128.0',
		'162.158.0.0',
		'104.16.0.0',
		'2400:cb00::',
		'2606:4700::',
		'2803:f800::',
		'2405:b500::',
		'2405:8100::'
		); // Some of CF's IPs to exclude (to avoid false results), if CF is being used
		$excl = array_merge((array)$excl_h, (array)$excl);
	}
	$c_ip = array(
	'0.0.0.0'
	); // IP exclusion list (client & header IP's), replace the placeholder IP with nothing or with an IP to exclude
	$excl = array_merge((array)$c_ip, (array)$excl);
	switch($type) {
	case 1:
                # Detect if IP contains headers (TYPE_1)
		if(!in_array($ip, $excl)) {
			foreach($proxy_h as $x) {
				if(isset($_SERVER[$x]) && $_SERVER[$x] != $ip && !in_array($_SERVER[$x], $excl)) {
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
		break;
        case 2:
		# Attempt to collect the potentially real IP (TYPE_2)
		$p_ip = $ext_m;
		if(!in_array($ip, $excl)) {
			foreach($proxy_h as $x){
				if(isset($_SERVER[$x]) && $_SERVER[$x] != $ip && $_SERVER[$x] != '' && !in_array($_SERVER[$x], $excl)) {
					$p_ip = $_SERVER[$x]; // If on proxy
				}
			}
		}
		if($p_ip == '') {
			$p_ip = $ext_m; // Exclusion (main IP)
		}
		return $p_ip;
		break;
	default:
		echo '<span style="color:red;font-weight:bold;">Error:</span> Invalid value set on first parameter'; // Error if there's no valid parameter value specified
		break;
        }
}
# FUNCTION END

echo '- - - - ProxDe - - - -';
echo '<br>';
echo '<br>';
if(real_ip(1) === False) {
	echo 'Your connection was found to be suspicious.'; // This should be obvious..
}
else {
	echo 'You\'ve passed detection.'; // Made it threw
}
echo '<br>';
echo real_ip(2);
?>
