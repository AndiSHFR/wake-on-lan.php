<?php //
/* 
 * PHPWOL - Send wake on lan magic packet from php.
 * PHP Version 5.6.28
 * @package PHPWOL
 * @see https://github.com/andishfr/wake-on-lan.php/ GitHub project
 * @author Andreas Schaefer <asc@schaefer-it.net>
 * @copyright 2017 Andreas Schaefer
 * @license https://github.com/AndiSHFR/wake-on-lan.php/blob/master/LICENSE MIT License
 * @note This program is distributed in the hope that it will be useful - WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.
 */

 /**
  * Wake On Lan function.
  *
	* @param string      $mac         The mac address of the host to wake
	* @param string      $ip          The hostname or ip address of the host to wake
	* @param string      $cidr        The cidr of the subnet to send to the broadcast address
	* @param string      $port        The udp port to send the packet to
  *
	* @return bool|string             false  = No error occured, string = Error message
	*/
function wakeOnLan($mac, $ip, $cidr, $port, &$debugOut) {
	// Initialize the result. If FALSE then everything went ok.
	$wolResult = false;
	// Initialize the debug output return
	$debugOut = [];  
	// Initialize the magic packet
	$magicPacket = str_repeat(chr(0xFF), 6);
			
	$debugOut[] = __LINE__ . " : wakeupOnLan('$mac', '$ip', '$cidr', '$port' );"; 
	
	// Test if socket support is available
	if(!$wolResult && !extension_loaded('sockets')) {
		$wolResult = 'Error: Extension <strong>php_sockets</strong> is not loaded! You need to enable it in <strong>php.ini</strong>';
		$debugOut[] = __LINE__ . ' : ' . $wolResult;
	}

	// Test if UDP datagramm support is avalable	
	if(!array_search('udp', stream_get_transports())) {
		$wolResult = 'Error: Cannot send magic packet! Tranport UDP is not supported on this system.';
		$debugOut[] = __LINE__ . ' : ' . $wolResult;
	}

	// Validate the mac address
	if(!$wolResult) {
		$debug[] = __LINE__ . ' : Validating mac address: ' . $mac; 
		$mac = str_replace(':','-',strtoupper($mac));
		$debugOut[] = __LINE__ . ' : MAC = ' . $mac;

		if ((!preg_match("/([A-F0-9]{2}[-]){5}([0-9A-F]){2}/",$mac)) || (strlen($mac) != 17)) {
			$wolResult = 'Error: Invalid MAC-address: ' . $mac;
			$debugOut[] = __LINE__ . ' : ' . $wolResult;
		}
	}

	// Finish the magic packet
	if(!$wolResult) {
		$debugOut[] = __LINE__ . ' : Creating the magic paket'; 
		$hwAddress = '';
		foreach( explode('-', $mac) as $addressByte) {
			$hwAddress .= chr(hexdec($addressByte)); 
		}
		$magicPacket .= str_repeat($hwAddress, 16);
	}
		
	// Resolve the hostname if not an ip address
	if(!$wolResult && !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ) {
		$debugOut[] = __LINE__ . ' : Resolving host :' . $ip;
		$tmpIp = gethostbyname($ip);
		if($ip==$tmpIp) {
			$wolResult = 'Error: Cannot resolve hostname "' . $ip . '".';
			$debugOut[] = __LINE__ . ' : ' . $wolResult;
		} else {
			$ip = $tmpIp; // Use the ip address
		}
	}
		
	// If $cidr is not empty we will use the broadcast address rather than the supplied ip address
	if(!$wolResult && '' != $cidr ) {
		$debugOut[] = __LINE__ . ' : CIDR is set to ' . $cidr . '. Will use broadcast address.';
		$cidr = intval($cidr);
		if($cidr < 0 || $cidr > 32) {
			$wolResult = 'Error: Invalid subnet size of ' . $cidr . '. CIDR must be between 0 and 32.';
			$debugOut[] = __LINE__ . ' : ' . $wolResult;			
		} else {
		  // Create the bitmask long from the cidr value
			$netMask = -1 << (32 - (int)$cidr);
			// Create the network address from the long of the ip and the network bitmask
			$networkAddress = ip2long($ip) & $netMask; 
      // Calulate the size fo the network (number of ip addresses in the subnet)
			$networkSize = pow(2, (32 - $cidr));
			// Calculate the broadcast address of the network by adding the network size to the network address
			$broadcastAddress = $networkAddress + $networkSize - 1;

			$debugOut[] = __LINE__ . ' : $netMask = ' . long2ip($netMask);
			$debugOut[] = __LINE__ . ' : $networkAddress = ' . long2ip($networkAddress);
			$debugOut[] = __LINE__ . ' : $networkSize = ' . $networkSize;
			$debugOut[] = __LINE__ . ' : $broadcastAddress = ' . long2ip($broadcastAddress);

			// Create the braodcast address from the long value and use this ip
			$ip = long2ip($broadcastAddress);
		}
	}

	// Validate the udp port
	if(!$wolResult && '' != $port ) {
		$port = intval($port);
		if($port < 0 || $port > 65535 ) {
			$wolResult = 'Error: Invalid port value of ' . $port . '. Port must between 1 and 65535.';
			$debugOut[] = __LINE__ . ' : ' . $wolResult;			
		}
	}		
		
	// Can we work with fsockopen/fwrite/fclose?
	if(!$wolResult &&	function_exists('fsockopen') ) {

		$debugOut[] = __LINE__ . " : Calling fsockopen('udp://$ip', $port, ... )";														

		// Open the socket
		$socket = @fsockopen('udp://' . $ip, $port, $errNo, $errStr);
		if(!$socket) {
			$wolResult = 'Error: ' . $errNo . ' - ' . $errStr;
			$debugOut[] = __LINE__ . ' : ' . $wolResult;											
		} else {
			$debugOut[] = __LINE__ . ' : Sending magic paket with ' . strlen($magicPacket) . ' bytes using fwrite().';														
			// Send the magic packet
			$writeResult = @fwrite($socket, $magicPacket);
			if(!$writeResult) {
				$lastError = error_get_last();
				$wolResult = 'Error: ' . $lastError['message'];
				$debugOut[] = __LINE__ . ' : ' . $wolResult;												
			}	else {
				$debugOut[] = __LINE__ . ' : Magic packet has been sent to address ' . $ip;
			}			
			// Clean up the socket
			fclose($socket);
			unset($socket);
		}

	} else 
		
		// Can we work with socket_create/socket_sendto/socket_close?
		if(!$wolResult && function_exists('socket_create') ) {
		
			$debug[] = __LINE__ . ' : Calling socket_create(AF_INET, SOCK_DGRAM, SOL_IDP)';														
			// Create the socket
			$socket = @socket_create(AF_INET, SOCK_DGRAM, SOL_UDP); // IPv4 udp datagram socket
			if(!$socket) {				
				$errno = socket_last_error();
				$wolResult = 'Error: ' . $errno . ' - ' . socket_strerror($errno); 
				$debug[] = __LINE__ . ' : ' . $wolResult;																
			}

			if(!$wolResult) {
				$debug[] = __LINE__ . ' : Calling socket_set_option($socket, SOL_SOCKET, SO_BROADCAST, true)';																	
				// Set socket options
				$socketResult = socket_set_option($socket, SOL_SOCKET, SO_BROADCAST, true);
				if(0 >= $socketResult) {
					$wolResult = 'Error: ' . socket_strerror($socketResult); 
					$debug[] = __LINE__ . ' : ' . $wolResult;													
				}
			}

			if(!$wolResult) {
				$debug[] = __LINE__ . ' : Sending magic packet using socket-sendto()...';																	
			  $socket_data = socket_sendto($socket, $buf, strlen($buf), $flags, $addr, $port);
  			if(!$socket_data) {
					$wolResult = 'Error: ' . socket_strerror($socketResult); 
					$debug[] = __LINE__ . ' : ' . $wolResult;													
 				DbOut("A magic packet of ".$socket_data." bytes has been sent via UDP to IP address: ".$addr.":".$port.", using the '".$function."()' function.");
 				}
			}
			
			if($socket) {
				socket_close($socket);
				unset($socket);			 
			}
		
	} else 
		if(!$wolResult) {
			$wolResult = 'Error: Cannot send magic packet. Neither fsockopen() nor'
			           . ' socket_create() is available on this system.';
	    $debugOut[] = __LINE__ . ' : ' . $wolResult;						
		}
	
  if(!$wolResult) $debugOut[] = __LINE__ . ' : Done.';

  return $wolResult;
}

function sendIcmpEchoRequest($host, $timeout = 1) {
	/* ICMP ping packet with a pre-calculated checksum */
	$package = "\x08\x00\x19\x2f\x00\x00\x00\x00\x70\x69\x6e\x67";
	$socket  = socket_create(AF_INET, SOCK_RAW, 1);
	socket_set_option($socket, SOL_SOCKET, SO_RCVTIMEO, array('sec' => $timeout, 'usec' => 0));
	socket_connect($socket, $host, null);
	$ts = microtime(true);
	socket_send($socket, $package, strLen($package), 0);
	if (socket_read($socket, 255)) {
			$result = microtime(true) - $ts;
	} else {
			$result = false;
	}
	socket_close($socket);
	return $result;
}

function endWithErrorMessage($message) {
  http_response_code(500);
	die('Internal Server Error! ' . $message);
}

function endWithJsonResponse($responseData) {

	array_walk_recursive($responseData, function(&$value, &$key) {
		if(is_string($value)) $value = utf8_encode($value);
	});

	$jsonString = json_encode($responseData, JSON_PRETTY_PRINT);

	if(!$jsonString) {
		http_response_code(500);
		die('Internal Server Error! Cannot convert response to JSON.');
	}

	header('Content-Length: ' . strlen($jsonString) );
	header('Content-Type: application/json');
	
	header('Expires: Mon, 26 Jul 1997 05:00:00:00 GMT');
	header('Last-Modified: ' . gmdate('D, d M Y H:i:s'));
  header('Cache-Control: no-cache, must-revalidate');
	header('Pragma: no-cache');
	die($jsonString);	
}




// Init locale variables
$MESSAGE = false;     // false -> all is fine, string -> error message
$DEBUGINFO = [];         // Array of strings containing debug information


// Get the url parameters
$ENABLEDEBUG = isset($_GET['debug'])   ? $_GET['debug']   : false; 
$OP          = isset($_GET['op'])      ? $_GET['op']      : '';
$MAC         = isset($_GET['mac'])     ? $_GET['mac']     : '';
$IP          = isset($_GET['ip'])      ? $_GET['ip']      : '';
$CIDR        = isset($_GET['cidr'])    ? $_GET['cidr']    : '';
$PORT        = isset($_GET['port'])    ? $_GET['port']    : '';
$COMMENT     = isset($_GET['comment']) ? $_GET['comment'] : '';


// Is it a "Get host state" request?
if('info'==$OP) {	
 if(''==$IP) endWithErrorMessage('Parameter IP not set.');
 $responseData = [ 'error' => false, 'isUp' => false ];

 $errStr = false;
 $errCode = 0;
 $waitTimeoutInSeconds = 3; 
 if($fp = @fsockopen($IP,3389,$errCode,$errStr,$waitTimeoutInSeconds)){   
	  fclose($fp);
  	$responseData['isUp'] = true;
	} else {
	$responseData['isUp'] = false;
	$responseData['errCode'] = $errCode;
	$responseData['errStr'] = $errStr;
 } 

 return endWithJsonResponse($responseData);
}

// Try to send the magic packet if at least a mac address and ip address was supplied
if('wol'===$OP && ''!==$MAC && '' != $IP) {

	$responseData = [ 'error' => false, 'data' => '' ];

	// Call to wake up the host
	$MESSAGE = wakeOnLan($MAC, $IP, $CIDR, $PORT, $DEBUGINFO);

	// If the request was with enabled debug mode then append the debug info to the response 
	// To enable debug mode add "&debug=1" to the url
	if($ENABLEDEBUG) $responseData['DEBUG'] = $DEBUGINFO;
	
	// Keep the message or make it an empty string
  if(!$MESSAGE) {
		$responseData['data'] = 'Magic packet has been sent for <strong>' . $MAC. '</strong>. Please wait for the host to come up...';
	} else {
		$responseData['error'] = $MESSAGE;
	}
	return endWithJsonResponse($responseData);	
}


// Try to send the magic packet if at least a mac address and ip address was supplied
if(''!==$MAC && '' != $IP) {
	// Call to wake up the host
	$MESSAGE = wakeOnLan($MAC, $IP, $CIDR, $PORT, $DEBUG);
  // Keep the message or make it an empty string
  if(!$MESSAGE) $MESSAGE = 'Magic packet has been sent for <strong>' . $MAC. '</strong>. Please wait for the host to come up...';
}

// Keep the message or make it an empty string
if(!$MESSAGE) $MESSAGE = '';

?><!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <!-- The above 3 meta tags *must* come first in the head; any other head content must come *after* these tags -->
    <title data-lang-ckey="wake-on-lan">Wake On LAN</title>

    <link href="//fonts.googleapis.com/css?family=Varela+Round" rel="stylesheet"> 
    <link rel="stylesheet" href="//maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" integrity="sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u" crossorigin="anonymous">
    <link rel="stylesheet" href="//maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap-theme.min.css" integrity="sha384-rHyoN1iRsVXV4nD0JutlnGaslCJuC7uwjduW9SVrLvRYooPp2bWYgmgJQIXwl/Sp" crossorigin="anonymous">
    <!--link rel="stylesheet" href="//maxcdn.bootstrapcdn.com/font-awesome/4.7.0/css/font-awesome.min.css"-->
 		
		<!--
    https://maxcdn.bootstrapcdn.com/bootswatch/3.3.7/cerulean/bootstrap.min.css
    https://maxcdn.bootstrapcdn.com/bootswatch/3.3.7/cosmo/bootstrap.min.css
    https://maxcdn.bootstrapcdn.com/bootswatch/3.3.7/cyborg/bootstrap.min.css
    https://maxcdn.bootstrapcdn.com/bootswatch/3.3.7/darkly/bootstrap.min.css
    https://maxcdn.bootstrapcdn.com/bootswatch/3.3.7/flatly/bootstrap.min.css
    https://maxcdn.bootstrapcdn.com/bootswatch/3.3.7/journal/bootstrap.min.css
		https://maxcdn.bootstrapcdn.com/bootswatch/3.3.7/lumen/bootstrap.min.css
		https://maxcdn.bootstrapcdn.com/bootswatch/3.3.7/paper/bootstrap.min.css
		https://maxcdn.bootstrapcdn.com/bootswatch/3.3.7/readable/bootstrap.min.css
		https://maxcdn.bootstrapcdn.com/bootswatch/3.3.7/sandstone/bootstrap.min.css
		https://maxcdn.bootstrapcdn.com/bootswatch/3.3.7/simplex/bootstrap.min.css
		https://maxcdn.bootstrapcdn.com/bootswatch/3.3.7/slate/bootstrap.min.css
		https://maxcdn.bootstrapcdn.com/bootswatch/3.3.7/solar/bootstrap.min.css
		https://maxcdn.bootstrapcdn.com/bootswatch/3.3.7/spacelab/bootstrap.min.css
		https://maxcdn.bootstrapcdn.com/bootswatch/3.3.7/superhero/bootstrap.min.css
		https://maxcdn.bootstrapcdn.com/bootswatch/3.3.7/united/bootstrap.min.css
		https://maxcdn.bootstrapcdn.com/bootswatch/3.3.7/yeti/bootstrap.min.css
		-->
    <!-- HTML5 shim and Respond.js for IE8 support of HTML5 elements and media queries -->
    <!-- WARNING: Respond.js doesn't work if you view the page via file:// -->
    <!--[if lt IE 9]>
      <script src="https://oss.maxcdn.com/html5shiv/3.7.3/html5shiv.min.js"></script>
      <script src="https://oss.maxcdn.com/respond/1.4.2/respond.min.js"></script>
    <![endif]-->

    <style>
      /*! Minimal styling here */
      body {
        font-family: 'Varela Round', 'Segoe UI', 'Trebuchet MS', sans-serif;
      }
  
			.ui-sortable tr {
				cursor:pointer;
			}
		
			.ui-sortable tr:hover {
				background:rgba(244,251,17,0.45);
			}

			.container-full {
				margin: 0 auto;
				width: 100%;
			}

	    .modal.modal-wide .modal-dialog { width: 80%; }
			.modal-wide .modal-body { overflow-y: auto; }

      .align-middle { vertical-align: middle !important; }

			.popover2{ display: block !important; max-width: 400px!important; width: auto; }

      footer { font-size: 80%; color: #aaa; }
      footer hr { margin-bottom: 5px; }

    </style>

  </head>
  <body>

  <!-- Container element for the page body -->
  <div class="container container-full">

		<div class="page-header">
			<h2><a href="https://github.com/AndiSHFR/wake-on-lan.php" data-lang-ckey="wake-on-lan">Wake On LAN</a></h2>
		</div>

  	<div class="row">
	  	<div class="col-xs-12 pageNotifications"></div>
  	</div>

		<div class="row">
			<div class="col-xs-12">
				<table id="items" class="table table-condensed xtable-bordered table-hover">
					<thead>
						<tr>
  						<th>&nbsp;</th>
							<th data-lang-ckey="mac-address">mac-address</th>
							<th data-lang-ckey="ip-or-host">ip-address</th>
							<th data-lang-ckey="cidr">subnet size (CIDR)</th>
							<th data-lang-ckey="port">port</th>
							<th data-lang-ckey="comment">comment</th>
							<th><button class="btn btn-xs btn-block btn-default" type="button" data-toggle="modal" data-target="#exportModal" data-lang-ckey="export">export...</button></th>
							<th><button class="btn btn-xs btn-block btn-default" type="button" data-toggle="modal" data-target="#importModal" data-lang-ckey="import">import...</button></th>
						</tr>
					</thead>
					
					<tbody></tbody>

					<tfoot>
						<tr>
	  					<td>&nbsp;</td>
							<td><input class="form-control" id="mac" placeholder="00:00:00:00:00:00" value=""></td>
							<td><input class="form-control" id="ip" placeholder="192.168.0.123" value=""></td>
							<td><input class="form-control" id="cidr" placeholder="24" value=""></td>
							<td><input class="form-control" id="port" placeholder="9" value="9"></td>
							<td><input class="form-control" id="comment" placeholder="my notebook" value="" data-lang-pkey="tpl-comment"></td>
							<td class="align-middle"><!-- button id="wakeItem" class="btn btn-sm btn-block btn-warning" type="button">Wake up!</button --></td>
							<td class="align-middle"><button id="addItem" class="btn btn-sm btn-block btn-success" type="button" data-lang-ckey="add">Add</button></td>
						</tr>
					</tfoot>
				</table>
			</div>
		</div>

    <footer>
        <hr>
        <p class="pull-right">Copyright &copy; 2017 Andras Schaefer &lt;asc@schaefer-it.net&gt;</p>

       <p class="pull-left">
			  <!-- https://www.iconfinder.com/icons/32338/flag_spain_spanish_flag_icon#size=16 -->
        <a href="#" data-lang-switch="de-DE"><img id="flag-de" title="Deutsch" alt="Deutsch" src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAABkUlEQVQ4jY3Ty27TQBSA4WOc2AE745mxnbEtobxCN8S5vGIfoizYFMTGkVjwAJUQm4oVrSOExIZ3qPN3EQcqtbkc6duc+XV2I/J8vBd257yJJyKvzuT9OzYajX6uVitmsxl1XbNYLI6q65q6rpnP53ie91F839/EcYxSCq01xpijtNYopYiiCM/z1jIMgtamKVmeM3GOsiwpnij3qoqiKHDOkec5xlp8329EwrCVNEWyHCkKpCz/q6rdzrlegUzcrrUpMhg08ncUtlgDLoPCQVWCm0CWgtWgDZg9DToBNYZxzNfAb+QmDFqsoUtTuszSWU1nTM/S2acMndF0iYI44sofNHIThC2JojMJnda70Bzw4gEZtkjEgyQ9zYPYA3RPgURcyaCRb5/Dll9jtvea7Z1he2dPMGzvE/gT8/7Sb+T7j7CFMZAABtCAPUD3TQLEfPgUNHJ7G24gBlQfnJL0bcz1ddDIZjP8Da+BsDc6Yd+9Yb32v4iIfSsyWU6nF8vp9N1ZqupiKWJWIuP02O88ax4BPEaWLPEaiXwAAAAASUVORK5CYII="></img></a>
        <a href="#" data-lang-switch="en-US"><img id="flag-en" title="English" alt="English" src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAACqklEQVQ4jY2Ta0iTARSGj1LURAVnWW3ewAxFy4Et5yxvoGQKZd7INDVn6TKvqdiypqGFpCIazghdidOo3ORLx8zmj1SwLdEmkvStUJCCknVBLfvx9kMhSDEfeDhw3sP5ceAQrcdqg95WMrIiIuvNlMvl1nK53HptdnWZd0TRTKS0DXm1vQhKa0ZJQx+EyY2Q3dXCL7EOVfeewylcjrnfWMe4+d1jcvLPMJ8oVMI1uhpxJUrsjZAjtUIFh9DryKzshm2wDHE1aih40XjtGIIRxzCMcIMxyQ1HMXGfkWdYDht6sRVROa04ltGI2IL7EKXWI+FKG4Rn65FcpoT76VoMtPdjediIBf0YFvSv8HPUhKbSawy5B11gD8XfQZS0BX7xtxEjVUCQUIuYSwr4J9YiOlcB3vFK6BQa/BgcxRfdCD4PjOLXywk0F8sY2uN/jj1T2gFemAzpsgfYF3oVmRUdcBAW4nxZG2z9LiNW9hD1tiIMc3yg2+ED3TZvDG8/iBLaxZBnSDbLFZchvVyJnYJ8SMrbQR4SSG90gNwyUFDdDeLE4+36G6JnYowhcjnFBqc0gPjpiEyrA+1OwcmcZpB9EpLyFSCbOESWtOMmeWOI+OgjPvqIBz3xUUQ2DDV19rKDb+agn/wArdEMvWkWWqMZQ6ZZ9BtZDE3NQW18j4/j0/huNMFinMJXgwkrJhYtVbcYelFZwy490sCiegJLZw8sXU9hUa33U5ca890azKs0mO9S41uPFo3ZeQwp9x9gJ4UiGIQiGAICYTjyHwMCYTgswnSAGFWurgzNLK+YN7jPllCPjTGki3KYhdQVSxJnLGbyV81yxqLkH7P+5ktZfCDXDYqj9loiDseF7LhiNy9fsYevQOwhEKzWjVzLeF6+YuLYBZGdneNm37kl/gDsSQH5dAvcewAAAABJRU5ErkJggg=="></img></a>
			 </p>

    </footer>

	</div>
      
		</div><!-- @end: .row -->

  </div><!-- @end: .container -->



	<!-- Export Modal -->
	<div class="modal modal-wide fade" id="exportModal" tabindex="-1" role="dialog" aria-labelledby="exportModal" aria-hidden="true">
  	<div class="modal-dialog">
        <div class="modal-content">
        	<div class="modal-header">
          		<button type="button" class="close" data-dismiss="modal">
              	<span aria-hidden="true">&times;</span>
                <span class="sr-only">Close</span>
              </button>
              <h4 class="modal-title" id="myModalLabel">Export Configuration</h4>
          </div>
            
          <div class="modal-body">                
            <form class="form-horizontal" role="form">
								<div class="col-sm-12">
									<textarea class="form-control" id="exportData" rows="5" style="resize: vertical" ></textarea>
									<small class="text-muted">To export your configuration copy the text from the field above and keep the configuration string.</small>
                </div>								
              </form>    
          </div>
            
          <div class="modal-footer">
                <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
          </div>
        </div>
    </div>
	</div>


	<!-- Import Modal -->
	<div class="modal modal-wide fade" id="importModal" tabindex="-1" role="dialog" aria-labelledby="importModal" aria-hidden="true">
	<div class="modal-dialog">
			<div class="modal-content">
					<div class="modal-header">
							<button type="button" class="close" data-dismiss="modal">
										 <span aria-hidden="true">&times;</span>
										 <span class="sr-only">Close</span>
							</button>
							<h4 class="modal-title" id="myModalLabel">Import Configuration</h4>
					</div>
					
					<div class="modal-body">                
							<form class="form-horizontal" role="form">
							<div class="form-group">
								<div class="col-sm-12">
									<textarea class="form-control" id="importData" rows="5" style="resize: vertical" ></textarea>
									<small class="text-muted">To import your configuration paste the configuration string into the field above and click the [Import] button below.</small>
								</div>
								</div>

								<div class="form-group">
									<div class="col-sm-offset-0 col-sm-12">
										<div class="checkbox">
											<label>
													<input type="checkbox" id="overwriteExisting"> Overwrite existing configuration
											</label>
										</div>
									</div>
								</div>

								</form>
							
	
					</div>
					
					<div class="modal-footer">
							<button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
							<button type="button" class="btn btn-primary" id="importConfiguration" >Import</button>
					</div>
			</div>
	</div>
</div>


  <!-- Script tags are placed at the end of the file to make html appearing faster -->
  <script src="//ajax.googleapis.com/ajax/libs/jquery/1.12.4/jquery.min.js"  crossorigin="anonymous"></script>
  <script src="//cdnjs.cloudflare.com/ajax/libs/jqueryui/1.12.1/jquery-ui.min.js" integrity="sha256-KM512VNnjElC30ehFwehXjx1YCHPiQkOPmqnrWtpccM=" crossorigin="anonymous"></script>
	<script src="//maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js" integrity="sha384-Tc5IQib027qvyjSMfHjOMaLkfuWVxZxUPnCJA7l2mCWNIpG9mGCD8wGNIcPD7Txa" crossorigin="anonymous"></script>
  
<script>
+function(window, $, undefined) {
    'use strict';
  
    // PRIVATE
  
        // Help overcome console issues under IE when dev tools are not enabled but debug is set to true.
    var console = (window.console = window.console || {}),
  
        // Global options for this module
        options = {
          // True will output debug information on the developer console
          debug: false,
          // css style to be applied to the element if the language text for the key was not found
          notFound: 'lang-not-found',
          // If set this points to a RESTful api to GET the language text
          api: undefined,
          // User callback to be called _before_ a text is assigned to an element.
          // If the callback returns true the default behaviour will not be executed.
          onItem: undefined,
          // Data cache for already loaded/used languages
          data: []
        },
  
        /**
         * Output debug information to the developer console
         *
         * @param {object} args_
         * @return
         * @api private
         */
        debug = function(args_) {
          if(options.debug) {
            var args = [].slice.call(arguments);
            args.unshift('mini-i18n: ');
            console.log.apply(null, args);
          }
        },  
  
        /**
         * Get a value from an object by its path
         *
         * @param {object} obj
         * @param {string} path
         * @return {object}
         * @api private
         */
        deepValue = function(obj, path) {
          if('string' !== typeof path) return obj;
          path = path.replace(/\[(\w+)\]/g, '.$1');   // convert indexes to properties
          path = path.replace(/^\./, '').split('.');  // strip a leading dot and split at dots
          var i = 0, len = path.length;               
          while(obj && i < len) {
            obj = obj[path[i++]];
          }
          return obj;
        },
  
        /**
         * Loops thru all language elements and sets the current language text
         * 
         * @param {string} lang
         * @return
         * @api private
         */
        updateElements = function(lang) {
          debug('Updating elements with language: ' + lang);
          var data = options.data[lang],  // data containing language related text. 
              // Callback called for every item to allow custom handling
              // If the callback returns false the default handling take place
              cb = options.onItem || function() { return false; }
              ;
  
          // Select all elements and loop thru them
            $('[data-lang-ckey],[data-lang-tkey],[data-lang-pkey]').each(function () {
              debug('Updating:', this); 
            var $this = $(this),                 // jQuery object of the element            
                ckey = $this.attr('data-lang-ckey'), // Key for the content of the element
                tkey = $this.attr('data-lang-tkey'), // Key for title attribute of the element
                pkey = $this.attr('data-lang-pkey'), // Key for placeholder attribute of the element
                cval = deepValue(data, ckey),      // Value of the content
                tval = deepValue(data, tkey),      // Value of the title attribute
                pval = deepValue(data, pkey)       // Value of the placeholder attribute
                ;
  
            // Execute callback and if the result is false run the default action
            if(false === cb(this, lang, ckey, cval, tkey, tval, pkey, pval)) {
              // If there is a content key set the content and handle "not found" condition
              if(ckey) {
                $this
                .removeClass(options.notFound)
                .html(cval)
                .addClass( (cval ? undefined : options.notFound ) );
              }          
              // If there is a title key set the title attribute and handle "not found" condition
              if(tkey) {
                $this
                .removeClass(options.notFound)
                .attr('title', (tval || $this.attr('title')) )
                .addClass( (tval ? undefined : options.notFound ) );
              }
              // If there is a placeholder key set the placeholder attribute and handle "not found" condition
              if(pkey) {
                $this
                .removeClass(options.notFound)
                .attr('placeholder', (pval || $this.attr('placeholder')) )
                .addClass( (pval ? undefined : options.notFound ) );
              }
            }
          });
        },
        
        /**
         * Sets configuration values 
         * 
         * @param {object} options_
         * @return
         * @api private
         */
        configure = function(options_) {
          debug('configure with: ', options_);
          options = $.extend({}, options, options_);
        },
  
        /**
         * Switch language text on elements
         * 
         * @param {string} lang
         * @return
         * @api private
         */
        language = function(lang) {        
          debug('Switch to language: ', lang);
          if(!options.data[lang] && options.url) {
            var url = options.url + lang;
            debug('Requesting language data for "' + lang + '" from url "' + url + '"');          
            $.ajax({
              url: url,
             success: function(res) { 
               debug('Got response.', res);          
               options.data[lang] = res;
             },
             complete: function(res) { 
               if(!options.data[lang]) {
                 debug('Got no valid response. Language "' + lang + '" will not be available!');          
                 options.data[lang] = {}; // Create an empty object so further requests won't lead to ajax calls anymore.
               }
               updateElements(lang);
              }
            });
          } else {
            updateElements(lang);
          }
        }
        ;
  
    // PUBLIC
  
    /**
     * Public mini-i18n method.
     * Can be called in two ways.
     * Setting options    : p is an object with configuration settings.
     * Switching language : p is a string with the language name. i.e. 'en-US'
     * 
     * @param {object|string} p 
     * @return
     * @api public
     */
    $.fn.extend({
      miniI18n : function(p) {
        if('string' === typeof p) return language(p);
        if('object' === typeof p) return configure(p);
        throw new Error('Argument must be a string or an object with configuration values.');
      }
    });
  
  
    $(function() {
      // Auto initialize elements with attribute "data-lang-switch"
      $('[data-lang-switch]').on('click.mini-i18n', function(e) {
        e.preventDefault();
        var lang = $(this).attr('data-lang-switch');
        if(lang) $.fn.miniI18n(lang);
      });
    });
  
  }(window, jQuery);

</script>

<script>
$(function () { 'use strict'

	/*!
		* Construct a dummy object for the console to make console usage more easier.
		* In IE the console object is undefined when the developer tools are not open.
		* This leads to an exception when using console.log(...); w/o dev tools opened.
		*/
	console = (window.console = window.console || { log: function() {} });

	var debug = <?php echo intval($ENABLEDEBUG); ?>;

  function pageNotify(msg, style, dismissable, autoClose) {
    if(!msg || '' === msg) { $('.pageNotifications').empty(); return };
    style = style || 'danger';
    dismissable = dismissable || false;
    autoClose = autoClose || 0;
  
    var $alert = $([
    '<div class="alert alert-' + style + ' alert-dismissable">',
    (dismissable ? '<a href="#" class="close" data-dismiss="alert" aria-label="close">&times;</a>' : '' ),
    '<span>' + (msg || '') + '</span>',
    '</div>'
    ].join(''));
  
    $('.pageNotifications').append($alert);
    if(0 < autoClose) {
      $alert.fadeTo(autoClose, 500).slideUp(500, function(){
        $alert.slideUp(500);
      });
    }
  }


  function addItemToTable(mac, ip, cidr, port, comment) {
		var $item = $([
			'<tr>'
		, '<td><i class="glyphicon glyphicon-thumbs-down text-danger" data-lang-tkey="state-title" title="Port tcp 3389 (RDP) reachable?"></i></td>'
		, '<td>', mac, '</td>'
		, '<td>', ip, '</td>'
		, '<td>', cidr, '</td>'
		, '<td>', port, '</td>'
		, '<td>', comment || '', '</td>'
		, '<td><button class="btn btn-xs btn-block btn-warning wakeItem" type="button" data-lang-ckey="wakeup">Wake up!</button></td>'
		, '<td><button class="btn btn-xs btn-block btn-danger removeItem" type="button" data-lang-ckey="remove">Remove</button></td>'
		, '</tr>'
		].join(''));
		$item.data('wol', { mac: mac, ip: ip, cidr:cidr, port:port, comment: comment });
    $('#items tbody').append($item);
	}

  function loadTable(json, append) {
    json = json || '[]';
		append = append || false;

    var items = $.parseJSON( json || '[]')
		    ;

    if(!append) $('#items tbody').empty();
		for(var i=0; i < items.length; i++) {
			var item = items[i];
			addItemToTable(item.mac, item.ip, item.cidr, item.port, item.comment);
		};
		$('#exportData').val(json);
	}

  function saveTableToLocalStorage() {
		// If local storage is not available then exit immediatly.
		if(!localStorage) return;
		var 
		    items = $('#items tbody tr').map(function() { return $(this).data('wol'); }).get()
			, json = JSON.stringify(items)
			  ;
		localStorage.setItem(STORAGE_ITEMNAME,json);
		$('#exportData').val(json);
	}

  
  var lastUpdateIndex = 0;
  function updateHostInfo() {
		var 
		    $tr = $('#items tbody tr:nth-child(' + (++lastUpdateIndex) + ')'),
			  $i = $tr.find('td:first-child >'),
				item = $tr.data('wol') || { },
				url= '?op=info&ip=' + item.ip
				;

    // No table row found then reset index to 0
    if(0===$tr.length) {
			lastUpdateIndex = 0; 
			setTimeout(updateHostInfo, 100);
			return;
		}
		
    // Make ajax request to get the state of the host
    $.ajax({
        url: url,
       type: 'GET',
       data: null,
       beforeSend: function(/* xhr */) { 
				$i
				  .removeClass('glyphicon-thumbs-down glyphicon-thumbs-up text-danger text-success')
				  .addClass('glyphicon-eye-open text-muted')
					;
			  },
       success:  function(resp) {
          if('string' === typeof resp) { resp = { error: resp }; }
          if(resp && resp.error && resp.error !== '') {
						return pageNotify(resp.error, 'danger', true, 10000);
          }

				if(resp.isUp) {
					$i
				  .removeClass('glyphicon-eye-open text-muted')
				  .addClass('glyphicon-thumbs-up text-success')
					;
				} else {
					$i
				  .removeClass('glyphicon-eye-open text-muted')
				  .addClass('glyphicon-thumbs-down text-danger')
					;
				}

          // Reschedule update
          setTimeout(updateHostInfo, 5000);
        },
       error: function(jqXHR, textStatus, errorThrown ) {
  				pageNotify('Error ' + jqXHR.status + ' calling "GET ' + url + '":' + jqXHR.statusText, 'danger', true, 10000);
        },
       complete: function(result) { 
  			}
      });

	}

	$.fn.miniI18n({ 
		debug: false,
    data: {
        'de-DE': {
					'wake-on-lan': 'Wake On LAN',
					'mac-address': 'MAC-Adresse',
					'ip-or-host': 'IP-Adresse oder Computername',
					'cidr': 'Subnetz Größe (CIDR)',
					'port': 'Port',
					'comment': 'Bemerkung',
					'export': 'Exportieren...',
					'import': 'Importieren...',
					'wakeup': 'Aufwecken!',
					'remove': 'Entfernen',
					'tpl-comment': 'Mein Notebook',
					'add': 'Hinzufügen',
					'state-title': 'Ist TCP Port 3389 (RDP) zu erreichen?'
        },
        'en-US': {
					'wake-on-lan': 'Wake On LAN',
					'mac-address': 'mac-address',
					'ip-or-host': 'ip-address or hostname',
					'cidr': 'subnet size (CIDR)',
					'port': 'port',
					'comment': 'Comment',
					'export': 'Export...',
					'import': 'Import...',
					'wakeup': 'Wake Up!',
					'remove': 'Remove',
					'tpl-comment': 'my notebook',
					'add': 'Add',
					'state-title': 'Port tcp 3389 (RDP) reachable?'
        }
      }
  });

  $.fn.miniI18n('en-US');


  $('#addItem').on('click', function(event) {
		event.preventDefault();
    addItemToTable($('#mac').val(), $('#ip').val(), $('#cidr').val(), $('#port').val(), $('#comment').val());
    saveTableToLocalStorage();
		return false;
	});

	$('#items tbody').on('click', '.removeItem', function(event) {
		event.preventDefault();
		var $tr = $(this).closest('tr')
		  , item = $tr.data('wol')
			  ;
		$('#mac').val(item.mac);
		$('#ip').val(item.ip);
		$('#cidr').val(item.cidr);
		$('#port').val(item.port);
		$('#comment').val(item.comment);
    $tr.remove();
		saveTableToLocalStorage();
		return false;
	});

	$('#items tbody').on('click', '.wakeItem', function(event) {
		event.preventDefault();

		var $tr = $(this).closest('tr'),
		    item = $tr.data('wol'),
				url= '?op=wol'
			  ;

    // Make ajax request to get the state of the host
    $.ajax({
        url: url,
       type: 'GET',
       data: { debug: debug, op:'wol', mac: item.mac, ip: item.ip, cidr: item.cidr, port: item.port},
       beforeSend: function(/* xhr */) { 
			  },
       success:  function(resp) {
          if('string' === typeof resp) { resp = { error: resp }; }
          if(resp && resp.error && resp.error !== '') {
						return pageNotify(resp.error, 'danger', true, 10000);
          }
					pageNotify(resp.data, 'success', true, 10000);          
        },
       error: function(jqXHR, textStatus, errorThrown ) {
  				pageNotify('Error ' + jqXHR.status + ' calling "GET ' + url + '":' + jqXHR.statusText, 'danger', true, 10000);
        },
       complete: function(result) { 
  			}
      });

	});


	  //Helper function to keep table row from collapsing when being sorted
		var fixHelperModified = function(e, tr) {
		var $originals = tr.children();
		var $helper = tr.clone();
		$helper.children().each(function(index) {
		  $(this).width($originals.eq(index).width())
		});
		return $helper;
  	};

	$('#importConfiguration').on('click', function(event) {
		event.preventDefault();
		var json = $('#importData').val()
		  , overwrite = $('#overwriteExisting').is(':checked')
		    ; 
    loadTable(json, !overwrite);		
		saveTableToLocalStorage();
		return false;
	});

  $("#items tbody").sortable({
    helper: fixHelperModified,
		stop: function(event,ui) { saveTableToLocalStorage(); }
	}).disableSelection();


  var 
	    STORAGE_ITEMNAME = 'wolItems'
		, msg = '<?php echo $MESSAGE; ?>';
			;

  if('' !== msg) pageNotify(msg, (msg.startsWith('Error') ? 'danger' : 'warning'), true, 10000);

  if(!localStorage) {
    pageNotify('<strong>Warning!</strong> Your browser does not support local storage. Changes to the list will be lost when closing the browser. You can use the export button to save the configuration string off your web browser.', 'warning', true, 10000);
	} else {
		loadTable(localStorage.getItem(STORAGE_ITEMNAME));
	}

  updateHostInfo();

});
</script>

  </body>
</html>
