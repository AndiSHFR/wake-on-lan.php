<?php
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
			$netMask = (1 << 32) - ( 1 << (32 - $cidr)) - 1;
			// Create the network address from the long of the ip and the network bitmask
			$networkAddress = ip2long($ip) & $netMask; 
			// Calculate the broadcast address of the network
			$broadcastAddress = $networkAddress + pow(2, (32 - $cidr)) - 1;
			
			$debugOut[] = __LINE__ . ' : $netMask = ' . long2ip($netMask);
			$debugOut[] = __LINE__ . ' : $networkAddress = ' . long2ip($networkAddress);
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
			$writeResult = fwrite($socket, $magicPacket);
			if(!$writeResult) {
				$wolResult = 'Error: ' . $errNo . ' - ' . $errStr;
				$debugOut[] = __LINE__ . ' : ' . $wolResult;												
			}	else {
				$debugOut[] = __LINE__ . ' : Magic packet has been send to address ' . $ip;
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
$MESSAGE= false;     // false -> all is fine, string -> error message
$DEBUG = [];         // Array of strings containing debug information

// Get the url parameters
$OP       = isset($_GET['op'])      ? $_GET['op']      : '';
$MAC      = isset($_GET['mac'])     ? $_GET['mac']     : '';
$IP       = isset($_GET['ip'])      ? $_GET['ip']      : '';
$CIDR     = isset($_GET['cidr'])    ? $_GET['cidr']    : '';
$PORT     = isset($_GET['port'])    ? $_GET['port']    : '';
$COMMENT  = isset($_GET['comment']) ? $_GET['comment'] : '';


// Is it a "Get host state" request?
if('info'===$OP && '' != $IP) {

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
	$MESSAGE = wakeOnLan($MAC, $IP, $CIDR, $PORT, $DEBUG);

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
    <title>Wake On LAN</title>

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
  <div class="container">

		<div class="page-header">
			<h2><a href="https://github.com/AndiSHFR/wake-on-lan.php">Wake On LAN</a></h2>
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
							<th>MAC-Address</th>
							<th>IP-Address or Hostname</th>
							<th>Network size (CIDR)</th>
							<th>Port</th>
							<th>Comment</th>
							<th><button class="btn btn-xs btn-block btn-default" type="button" data-toggle="modal" data-target="#exportModal">Export</button></th>
							<th><button class="btn btn-xs btn-block btn-default" type="button" data-toggle="modal" data-target="#importModal">Import</button></th>
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
							<td><input class="form-control" id="comment" placeholder="my notebook" value=""></td>
							<td class="align-middle"><!-- button id="wakeItem" class="btn btn-sm btn-block btn-warning" type="button">Wake up!</button --></td>
							<td class="align-middle"><button id="addItem" class="btn btn-sm btn-block btn-success" type="button">Add</button></td>
						</tr>
					</tfoot>
				</table>
			</div>
		</div>

    <footer>
        <hr>
        <p class="pull-right">Copyright &copy; 2017 Andras Schaefer &lt;asc@schaefer-it.net&gt;</p>
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
$(function () { 'use strict'

	/*!
		* Construct a dummy object for the console to make console usage more easier.
		* In IE the console object is undefined when the developer tools are not open.
		* This leads to an exception when using console.log(...); w/o dev tools opened.
		*/
	console = (window.console = window.console || { log: function() {} });

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
		, '<td><i class="glyphicon glyphicon-thumbs-down text-danger"></i></td>'
		, '<td>', mac, '</td>'
		, '<td>', ip, '</td>'
		, '<td>', cidr, '</td>'
		, '<td>', port, '</td>'
		, '<td>', comment || '', '</td>'
		, '<td><button class="btn btn-xs btn-block btn-warning wakeItem" type="button">Wake up!</button></td>'
		, '<td><button class="btn btn-xs btn-block btn-danger removeItem" type="button">Remove</button></td>'
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

  var lastUpdateIndex = 1;
  function updateHostInfo() {
		console.log()
		var 
		    $tr = $('#items tbody tr:nth-child(' + lastUpdateIndex + ')'),
			  $i = $tr.find('td:first-child >'),
				item = $tr.data('wol') || {},
				url= '?op=info&ip=' + item.ip
				;

    // Now table row found then reset index to 0
    if(0===$tr.length) lastUpdateIndex = 1; else lastUpdateIndex++;

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
  				pageNotify('Error ' + jqXHR.status + ' calling "GET ' + uri + '":' + jqXHR.statusText, 'danger', true, 10000);
        },
       complete: function(result) { 
  			}
      });

	}

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
       data: { op:'wol', mac: item.mac, ip: item.ip, cidr: item.cidr, port: item.port},
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
  				pageNotify('Error ' + jqXHR.status + ' calling "GET ' + uri + '":' + jqXHR.statusText, 'danger', true, 10000);
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
