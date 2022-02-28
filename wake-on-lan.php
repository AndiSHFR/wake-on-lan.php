<?php //
/* 
 * PHPWOL - Send wake on lan magic packet from php.
 * PHP Version 5.6.28
 * @package PHPWOL
 * @see https://github.com/andishfr/wake-on-lan.php/ GitHub project
 * @author Andreas Schaefer <asc@schaefer-it.net>
 * @copyright 2021 Andreas Schaefer
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
            
      // Can we work with socket_create/socket_sendto/socket_close?
      if(!$wolResult && function_exists('socket_create') ) {
      
        $debug[] = __LINE__ . ' : Calling socket_create(AF_INET, SOCK_DGRAM, SOL_UDP)';														
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
          $flags = 0;															
          $socket_data = socket_sendto($socket, $magicPacket, strlen($magicPacket), $flags, $ip, $port);
          if(!$socket_data) {
            $wolResult = 'Error: ' . socket_strerror($socketResult); 
            $debug[] = __LINE__ . ' : ' . $wolResult;													
            //DbOut("A magic packet of ".$socket_data." bytes has been sent via UDP to IP address: ".$addr.":".$port.", using the '".$function."()' function.");
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
  

function safeGet($data, $key, $default) { 
  return isset($data) && isset($data[$key]) ? $data[$key] : $default; 
}

function endWithErrorMessage($message) {
  http_response_code(500);
	die('Internal Server Error! ' . $message);
}

function endWithJsonResponse($responseData, $filename = NULL) {

  if($responseData) {
    array_walk_recursive($responseData, function(&$value, &$key) {
      if(is_string($value)) $value = utf8_encode($value);
    });  
  }

	$jsonString = json_encode($responseData, JSON_PRETTY_PRINT);

	if(!$jsonString) endWithErrorMessage('Cannot convert response data to JSON.');

	header('Content-Length: ' . strlen($jsonString) );
	header('Content-Type: application/json');	
	header('Expires: Mon, 26 Jul 1997 05:00:00:00 GMT');
	header('Last-Modified: ' . gmdate('D, d M Y H:i:s'));
  header('Cache-Control: no-cache, must-revalidate');
	header('Pragma: no-cache');
  if($filename) {
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    header('Content-Transfer-Encoding: binary');
  }
  die($jsonString);	
}


/**
 * Initialize required variables 
 */
$configFilename = __DIR__ . DIRECTORY_SEPARATOR . 'config.json';
$requestMethod = $_SERVER['REQUEST_METHOD'];

$isSocketExtensionLoaded = intval(extension_loaded('sockets'));
$isDebugEnabled = intval(safeGet($_GET, 'debug', false));
$ajaxOperation = safeGet($_POST, 'aop', safeGet($_GET, 'aop', ''));


/**
 * See if we have any ajax request
 */
if('CONFIG.GET'===$ajaxOperation) {
  $jsonData = [];
  if(file_exists($configFilename)) {
    $jsonString = file_get_contents($configFilename);
    $jsonData = json_decode($jsonString, true);
  }
  endWithJsonResponse($jsonData);
} else

if('CONFIG.SET'===$ajaxOperation && 'POST'==$requestMethod) {
    $phpInput = file_get_contents('php://input');
    $jsonData = json_decode($phpInput);
    $jsonString = json_encode($jsonData, JSON_PRETTY_PRINT);
    if(!file_put_contents($configFilename, $jsonString)) {
      endWithErrorMessage('Cannot write configuration file.<br/>Please make sure the web server can write to the folder.');
    }
    endWithJsonresponse([ 'status' => 'OK']);  
} else

if('CONFIG.DOWNLOAD'===$ajaxOperation) {
  $jsonData = [];
  if(file_exists($configFilename)) {
    $jsonString = file_get_contents($configFilename);
    $jsonData = json_decode($jsonString, true);
  }
  endWithJsonResponse($jsonData, 'wake-on-lan-' . date('Ymd-His') . '.json' );
} else

if('HOST.CHECK'===$ajaxOperation) {
  $HOST_CHECK_PORTS = [ '3389' => '3389 (RDP)', '22' => '22 (SSH)', '80' => '80 (HTTP)', '443' => '443 (HTTPS)' ]; 
  $host = safeGet($_GET, 'host', null);
  if(!$host) endWithErrorMessage('Parameter host not set.');
  $responseData = [ 'error' => false, 'isUp' => false ];

  $errStr = false;
  $errCode = 0;
  $waitTimeoutInSeconds = 3; 

  foreach($HOST_CHECK_PORTS as $port=>$info) {
    if($responseData['isUp']) break;
    if($fp = @fsockopen($host,$port,$errCode,$errStr,$waitTimeoutInSeconds)){   
      fclose($fp);
      $responseData['isUp'] = true;
      $responseData['info'] = $info;
      $responseData['errCode'] = '';
      $responseData['errStr'] = '';
      $responseData['errorPort'] = '';
    } else {
    $responseData['isUp'] = false;
    $responseData['errCode'] = $errCode;
    $responseData['errStr'] = $errStr;
    $responseData['errorPort'] = $port;
   }    
  }

  return endWithJsonResponse($responseData);
} else

if('HOST.WAKEUP'===$ajaxOperation) {

	$responseData = [ 'error' => false, 'data' => '' ];
  $DEBUGINFO = [];

  $mac = safeGet($_GET, 'mac', '');

	// Call to wake up the host
	$MESSAGE = wakeOnLan(
    $mac
  , safeGet($_GET, 'host', '')
  , safeGet($_GET, 'cidr', '')
  , safeGet($_GET, 'port', '')
  , $debugOut
  );

	// If the request was with enabled debug mode then append the debug info to the response 
	// To enable debug mode add "&debug=1" to the url
	if($isDebugEnabled) $responseData['DEBUG'] = $DEBUGINFO;

  if($MESSAGE) {
    endWithErrorMessage($MESSAGE);
  } else {
    endWithJsonResponse([
      'info' => 'Magic packet has been sent for <strong>' . $mac. '</strong>. Please wait for the host to come up...'
    ]);
  }
} else {
  if(isset($_GET['aop'])) endWithErrorMessage('Invalid value for aop!');
}


?><!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="description" content="Web based user interface to send wake-on-lan magic packets.">
    <meta name="author" content="Andreas Schaefer">
    <title data-lang-ckey="title">Wake On Lan</title>

    <link rel="canonical" href="https://www.github.com/AndiSHFR/wake-on-lan.php">

    <link href="//fonts.googleapis.com/css?family=Varela+Round" rel="stylesheet"> 
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-1BmE4kWBq78iYhFldvKuhfTAU6auU8tT94WrHftjDbrCEXSU1oBoqyl2QvZ6jIW3" crossorigin="anonymous">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@5.15.4/css/all.min.css" integrity="sha256-mUZM63G8m73Mcidfrv5E+Y61y7a12O5mW4ezU3bxqW4=" crossorigin="anonymous">
        
    <style>
    body { font-family: 'Varela Round', 'Segoe UI', 'Trebuchet MS', sans-serif; }
    #ajaxLoader { margin-left: 10px; display: none; }
    .dropdown-item i { min-width: 1.5em; }
    .ui-sortable tr { cursor:pointer; }
    .ui-sortable-helper { display: table; }
 
    .unsaved-changes:after {
      content: '';
      width: 0;
      height: 0;
      border-style: solid;
      border-width: 0 60px 60px 0;
      border-color: transparent #e67219 transparent transparent;
      right: 0;
      top: 0;
      position: absolute;
    }

    #pageContainer { padding: 5px; margin: auto; }

    footer { font-size: 80%; }
    </style>
    
  </head>
  <body>

    <div id="pageContainer" class="_container _container-fluid">  

      <header class="d-flex flex-wrap justify-content-center py-3 mb-4 border-bottom">
        <a href="/" class="d-flex align-items-center mb-3 mb-md-0 me-md-auto text-dark text-decoration-none">
          <svg class="bi me-2" width="40" height="32"><use xlink:href="#"/></svg>
          <span class="fs-4" data-lang-ckey="title">Wake On Lan</span>
          <img id="ajaxLoader" src="data:image/gif;base64,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"></img>
        </a>

        <ul class="nav nav-pills">
          <li class="nav-item"><a href="https://www.github.com/AndiSHFR/Wake-on-lan.php" class="nav-link">GitHub</a></li>          
          <li class="nav-item">
            <div class="dropdown text-end">
              <a href="#" class="nav-link dropdown-toggle" id="dropdownTools" data-bs-toggle="dropdown" aria-expanded="false" data-lang-ckey="tools">Tools</a>
                <ul class="dropdown-menu text-small" aria-labelledby="dropdownTools">
                <li><a id="downloadConfig" class="dropdown-item" href="?aop=CONFIG.DOWNLOAD"><i class="fa fa-file-csv"></i> <span data-lang-ckey="download_config">Download Configuration</span></a></li>
                <li><a id="exportConfig" class="dropdown-item" data-bs-toggle="modal" data-bs-target="#exportModal" href="#"><i class="fa fa-file-export"></i> <span data-lang-ckey="export_config">Export Configuration</span></a></li>
                <li><a id="importConfig" class="dropdown-item" data-bs-toggle="modal" data-bs-target="#importModal" href="#"><i class="fa fa-file-import"></i> <span data-lang-ckey="import_config">Import Configuration</span></a></li>
                <li><hr class="dropdown-divider"></li>
                <li><a id="loadConfigFromServer" class="dropdown-item" href="#"><i class="fa fa-folder-open"></i> <span data-lang-ckey="load_config">Load Configuration</span></a></li>
                <li><a id="saveConfigToServer" class="dropdown-item" href="#"><i class="fa fa-save"></i> <span data-lang-ckey="save_config">Save Configuration</span></a></li>
              </ul>
            </div>
          </li>          
        </ul>

        </header>

      <div id="notificationContainer"></div>

      <table id="hostTable" class="table table-sm table-hover">
        <colgroup>
          <col style="min-width: 2em;">
        </colgroup>
        <thead>
          <th></th>
          <th data-lang-ckey="mac_address">Mac-Address</th>
          <th data-lang-ckey="ip_or_hostname">Ip-Address or Hostname</th>
          <th data-lang-ckey="subnet">Subnet Size (CIDR)</th>
          <th data-lang-ckey="port">Port</th>
          <th data-lang-ckey="comment">Comment</th>
          <th></th>
        <thead>

        <tbody>
        </tbody>

        <tfoot>
          <tr>
            <td class="align-middle"></td>
            <td class="align-middle"><input id="mac" type="text" class="form-control" value="" placeholder="Mac-Address here"  data-lang-pkey="p_mac_address"/></td>
            <td class="align-middle"><input id="host" type="text" class="form-control" value="" placeholder="Ip or Hostname here"  data-lang-pkey="p_ip_or_hostname"/></td>
            <td class="align-middle"><input id="cidr" type="text" class="form-control" value="" placeholder="Subnet Size here"  data-lang-pkey="p_ip_subnet"/></td>
            <td class="align-middle"><input id="port" type="text" class="form-control" value="" placeholder="Port here"  data-lang-pkey="p_port"/></td>
            <td class="align-middle"><input id="comment" type="text" class="form-control" value="" placeholder="Comment here" data-lang-pkey="p_comment"/></td>
            <td class="align-middle">
              <div class="d-flex flex-row justify-content-end">
                <button type="button" id="addHost" class="btn btn-outline-primary btn-sm mx-1"><i class="fa fa-plus"></i></button>
              </div>
            </td>
          </tr>
        </tfoot>
      </table>


      <footer class="d-flex flex-wrap justify-content-between">

        <p class="col-6">
  			  <!-- https://www.iconfinder.com/icons/32338/flag_spain_spanish_flag_icon#size=16 -->
          <a href="#" data-lang-switch="de-DE"><img id="flag-de" title="Deutsch" alt="Deutsch" src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAABkUlEQVQ4jY3Ty27TQBSA4WOc2AE745mxnbEtobxCN8S5vGIfoizYFMTGkVjwAJUQm4oVrSOExIZ3qPN3EQcqtbkc6duc+XV2I/J8vBd257yJJyKvzuT9OzYajX6uVitmsxl1XbNYLI6q65q6rpnP53ie91F839/EcYxSCq01xpijtNYopYiiCM/z1jIMgtamKVmeM3GOsiwpnij3qoqiKHDOkec5xlp8329EwrCVNEWyHCkKpCz/q6rdzrlegUzcrrUpMhg08ncUtlgDLoPCQVWCm0CWgtWgDZg9DToBNYZxzNfAb+QmDFqsoUtTuszSWU1nTM/S2acMndF0iYI44sofNHIThC2JojMJnda70Bzw4gEZtkjEgyQ9zYPYA3RPgURcyaCRb5/Dll9jtvea7Z1he2dPMGzvE/gT8/7Sb+T7j7CFMZAABtCAPUD3TQLEfPgUNHJ7G24gBlQfnJL0bcz1ddDIZjP8Da+BsDc6Yd+9Yb32v4iIfSsyWU6nF8vp9N1ZqupiKWJWIuP02O88ax4BPEaWLPEaiXwAAAAASUVORK5CYII="></img></a>
          <a href="#" data-lang-switch="en-US"><img id="flag-en" title="English" alt="English" src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAACqklEQVQ4jY2Ta0iTARSGj1LURAVnWW3ewAxFy4Et5yxvoGQKZd7INDVn6TKvqdiypqGFpCIazghdidOo3ORLx8zmj1SwLdEmkvStUJCCknVBLfvx9kMhSDEfeDhw3sP5ceAQrcdqg95WMrIiIuvNlMvl1nK53HptdnWZd0TRTKS0DXm1vQhKa0ZJQx+EyY2Q3dXCL7EOVfeewylcjrnfWMe4+d1jcvLPMJ8oVMI1uhpxJUrsjZAjtUIFh9DryKzshm2wDHE1aih40XjtGIIRxzCMcIMxyQ1HMXGfkWdYDht6sRVROa04ltGI2IL7EKXWI+FKG4Rn65FcpoT76VoMtPdjediIBf0YFvSv8HPUhKbSawy5B11gD8XfQZS0BX7xtxEjVUCQUIuYSwr4J9YiOlcB3vFK6BQa/BgcxRfdCD4PjOLXywk0F8sY2uN/jj1T2gFemAzpsgfYF3oVmRUdcBAW4nxZG2z9LiNW9hD1tiIMc3yg2+ED3TZvDG8/iBLaxZBnSDbLFZchvVyJnYJ8SMrbQR4SSG90gNwyUFDdDeLE4+36G6JnYowhcjnFBqc0gPjpiEyrA+1OwcmcZpB9EpLyFSCbOESWtOMmeWOI+OgjPvqIBz3xUUQ2DDV19rKDb+agn/wArdEMvWkWWqMZQ6ZZ9BtZDE3NQW18j4/j0/huNMFinMJXgwkrJhYtVbcYelFZwy490sCiegJLZw8sXU9hUa33U5ca890azKs0mO9S41uPFo3ZeQwp9x9gJ4UiGIQiGAICYTjyHwMCYTgswnSAGFWurgzNLK+YN7jPllCPjTGki3KYhdQVSxJnLGbyV81yxqLkH7P+5ktZfCDXDYqj9loiDseF7LhiNy9fsYevQOwhEKzWjVzLeF6+YuLYBZGdneNm37kl/gDsSQH5dAvcewAAAABJRU5ErkJggg=="></img></a>
          <a href="#" data-lang-switch="es-ES"><img id="flag-es" title="Española" alt="Española" src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAAXNSR0IArs4c6QAAAhNJREFUOE+NkzFoE2EUx3/f3SVparFRoq22SaQHDhZrKJymIgq6ODhadHHsIjgIzlIHNycdBTvc0EgFa4gaECuCDg2FEiklhasQoVZpQVotNuflTr7cHZZWG9/4vu/93v//3vcJdoYAvL/kZWrHmUyEIUb9Cy1j9E8DTzxriy+cGhw8aju/QAgQyu4CPLdZHhOCUnn6iXgEi0OofXVUQBa3EiHduXTgMIb7XMyu5KxsUtdl0i/+H4CEaOSnZoqiXM5ahpHSfVuhAsEmGku1BpGoR9chiOEE1sIGEUxzLgQc3gKQEJvKgyUqTz/hLK+Tu3GEY9fTwXBlowagYprLIeCg7kuXNmwm8jYXvn+jcKtKz/1xTlxZ4K05yfBIIlAh7xECjluGcUD3qZJu8+7OSTrKY8wn2+i8WCLdM8da4RVn7n0EIkEjgWl+lgokIBEokCpsyrdzxLpM3rxI0Gl7nD2/wdcfw5y+OwNEtwP6LcPYt2UGDg8nhzi3Ns78e4XeDw7d1yK8zFxm5NJ0c/rhxkzzS1HMWv1WVpeA8KW6rLKXJBts0o2HR5wVVomTZD3YlLQqeFxYLoqpq9HFbG+0z5YjaA5SQdVcGg2BovjDcj0FVfFoOHJDMuexR/XIV+tFUblJbWCANPVta/7Xj/CbQztMvKYkiO9PaZqWymQyvj9pcbdwwHF+UqvVBFp7tdW7bfkzfwPxEcg6YixgfwAAAABJRU5ErkJggg=="></img></a>
  			</p>

        <p class="col-6 text-muted text-end">&copy; 2021 Andreas Schaefer &lt;asc@schaefer-it.net&gt;</p>

      </footer>

    </div>

    <div class="modal fade" id="chooseLoadConfigModal" data-bs-backdrop="static" data-bs-keyboard="false" tabindex="-1" aria-labelledby="staticBackdropLabel" aria-hidden="true">
      <div class="modal-dialog">
        <div class="modal-content">
          <div class="modal-header">
            <h5 class="modal-title" id="staticBackdropLabel" data-lang-ckey="c_load_configuration">Loading Configuration</h5>
            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
          </div>
          <div class="modal-body">        
            <p data-lang-ckey="c_replace_config">Do you want to <strong>replace</strong> the existing configuration?</p>
            <p data-lang-ckey="c_append_config">Or do you want to <strong>append to</strong> the existing configuration?</p>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
            <button type="button" class="btn btn-warning" data-choice="REPLACE">Replace Existing</button>
            <button type="button" class="btn btn-success" data-choice="APPEND">Append To Existing</button>
          </div>
        </div>
      </div>
    </div>

    <div class="modal fade" id="importModal" data-bs-backdrop="static" data-bs-keyboard="false" tabindex="-1" aria-labelledby="staticBackdropLabel" aria-hidden="true">
      <div class="modal-dialog modal-lg">
        <div class="modal-content">
          <div class="modal-header">
            <h5 class="modal-title" id="staticBackdropLabel">Import Configuration</h5>
            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
          </div>
          <div class="modal-body">        

            <div id="importJsonErrorContainer"></div>

            <div class="mb-3">
              <label for="importJson" class="form-label">JSON Configuration</label>
              <textarea id="importJson" class="form-control" aria-describedby="importJsonHelpBlock" rows="6"></textarea>
              <div id="importJsonHelpBlock" class="form-text">
              To import your configuration, paste the configuration json into the field above and click the <strong>[Import]</strong> button below.
              </div>
            </div>
         
            <div class="mb-3 form-check">
              <input type="checkbox" class="form-check-input" id="importJsonOverwriteExisting">
              <label class="form-check-label" for="importJsonOverwriteExisting">Overwrite exiting configuration</label>
            </div>

          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
            <button type="button" id="importJsonConfig" class="btn btn-primary" >Import</button>
          </div>
        </div>
      </div>
    </div>

    <div class="modal fade" id="exportModal" data-bs-backdrop="static" data-bs-keyboard="false" tabindex="-1" aria-labelledby="staticBackdropLabel" aria-hidden="true">
      <div class="modal-dialog modal-lg">
        <div class="modal-content">
          <div class="modal-header">
            <h5 class="modal-title" id="staticBackdropLabel">Export Configuration</h5>
            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
          </div>
          <div class="modal-body">        

            <div class="mb-3">
              <label for="exportJson" class="form-label">JSON Configuration</label>
              <textarea id="exportJson" class="form-control" aria-describedby="importJsonHelpBlock" rows="6"></textarea>
              <div id="importJsonHelpBlock" class="form-text">
              Copy the contents of the edit field from above and save it to a json file.
              </div>
            </div>
         
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
          </div>
        </div>
      </div>
    </div>


    <script id="tableRowTemplate" type="text/template">
    <tr data-wol='{{this.dataWol}}'>
      <td class="align-middle"><i class="fa fa-question"></i></td>
      <td class="align-middle">{{this.mac}}</td>
      <td class="align-middle">{{this.host}}</td>
      <td class="align-middle">{{this.cidr}}</td>
      <td class="align-middle">{{this.port}}</td>
      <td class="align-middle">{{this.comment}}</td>
      <td class="align-middle">
        <div class="d-flex flex-row justify-content-end">
          <button type="button" class="btnWakeUpHost btn btn-outline-success btn-sm mx-1"><i class="fa fa-rocket"></i></button>
          <button type="button" class="btnRemoveHost btn btn-outline-danger btn-sm mx-1"><i class="fa fa-trash-alt"></i></button>
        </div>
      </td>
    </tr>
  </script>

  <script id="textNoSocketExtensionLoaded" type="text/template">
    <h4 class="alert-heading">Sockets Extension Not Loaded!</h4>
    <p>Please enable the sockets extension in your <code>php.ini</code> to enable sending the magic packet.</p>
  </script>

  <script id="textConfigSavedSucessfully" type="text/template">
    <h4 class="alert-heading">Configuration saved.</h4>
    <p>Your configuration was successfully saved to the server.</p>
  </script>
  
  <script id="textConfirmUnsavedChanged" type="text/template">
  It looks like you have been editing something. If you leave before saving, your changes will be lost.
  </script>

 
  <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.10.2/dist/umd/popper.min.js" integrity="sha384-7+zCNj/IqJ95wo16oMtfsKbZ9ccEh31eOz1HGyDuCQ6wgnyJNSYdrPa03rtR1zdB" crossorigin="anonymous"></script>
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.min.js" integrity="sha384-QJHtvGhmr9XOIpI6YVutG+2QOK9T+ZnN4kzFN1RtK3zEFEIsxhlmWl5/YESvpZ13" crossorigin="anonymous"></script>
  <script src="https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js" integrity="sha256-/xUj+3OJU5yExlq6GSYGSHk7tPXikynS7ogEvDej/m4=" crossorigin="anonymous"></script>
  <script src="https://cdn.jsdelivr.net/npm/jquery-ui-bundle@1.12.1/jquery-ui.min.js" integrity="sha256-Pbq2xgNJP86oOUVTdJMo7QWsoY7QYPL0mF5cJ0vj8Xw=" crossorigin="anonymous"></script>


<script language="javascript" type="text/javascript">
/*!
 * mini-i18n.js JavaScript Library v1.0.0 
 * http://github.com/AndiSHFR/mini-i18n/
 * 
 * Copyright 2017 Andreas Schaefer
 * Licensed under the MIT license
 * 
 * @file 
 * JavaScript module to switch text elements in a web page on the fly.
 * The intended use is for switching display language on a web page.
 * For language IDs see http://www.localeplanet.com/icu/iso639.html 
 *                   or https://en.wikipedia.org/wiki/List_of_ISO_639-1_codes
 */

if ('undefined' === typeof jQuery) {
  throw new Error('mini-i18n\'s JavaScript requires jQuery.')
}

+function ($) {
  'use strict';
  var version = $.fn.jquery.split(' ')[0].split('.')
  if ((version[0] < 2 && version[1] < 9) || (version[0] == 1 && version[1] == 9 && version[2] < 1) || (version[0] > 3)) {
    throw new Error('mini-i18n\'s JavaScript requires jQuery version 1.9.1 or higher, but lower than version 4. You are using version ' + $.fn.jquery);
  }
}(jQuery);



+function(window, $, undefined) { "use strict";

  // PRIVATE
  var     
    err = undefined,    
    // Available language texts strings
    languageData = {},
    // Global options for this module
    options = {
      // True will output debug information on the developer console
      debug: false,
      // Current language. i.e. en-US or de-DE       
      language: '',
      // css style to be applied to the element if the language text for the key was not found
      notFound: 'lang-not-found',
      // Uri to download locale texts. Must contain language placeholder. i.e. /locale/{{LANG}}.json
      source: undefined,
      // User callback to be called _before_ a text is assigned to an element.
      // If the callback returns true the default behaviour will not be executed.
      onItem: undefined,
      // User function called after the localization has taken place. 
      changed: undefined,
      // Either the language data, a callback to return the language data or an url to fetch the language data
      data: undefined
    },

    /**
     * Output debug information to the developer console
     *
     * @param {object} args_
     * @return
     * @api private
     */
    debug = function(args_) {
      if(console && options.debug) {
        var args = [].slice.call(arguments);
        args.unshift('** MINI-I18N: ');
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
      if(!path) return null;
      if('' === path) return obj;
      path = path.replace(/\[(\w+)\]/g, '.$1');   // convert indexes to properties
      path = path.replace(/^\./, '').split('.');  // strip a leading dot and split at dots
      var i = 0, len = path.length;               
      while(obj && i < len) {
        obj = obj[path[i++]];
      }
      return obj;
    },

    explainAjaxError = function (jqXHR, textStatus, errorThrown) {
      var 
        knownErrors = {
          0: 'Not connected. Please verify your network connection.',
          404: '404 - The requested page could not be found.',
          500: '500 - Internal Server Error.', 
          'parseerror': 'Parsing requested JSON result failed.',
          'timeout': 'Time out error.',
          'abort': 'Ajax request aborted.'
        }
        ;

      return {
        error: knownErrors[jqXHR.status] || 'Unknown Error Reason ' + jqXHR.status,
        details: jqXHR.responseText
      };
    },

    parseIniString = function(data){
      var regex = {
          section: /^\s*\[\s*([^\]]*)\s*\]\s*$/,
          param: /^\s*([^=]+?)\s*=\s*(.*?)\s*$/,
          comment: /^\s*;.*$/
      };
      var value = {};
      var lines = data.split(/[\r\n]+/);
      var section = null;
      lines.forEach(function(line){
          if(regex.comment.test(line)){
              return;
          }else if(regex.param.test(line)){
              var match = line.match(regex.param);
              if(section){
                  value[section][match[1]] = match[2];
              }else{
                  value[match[1]] = match[2];
              }
          }else if(regex.section.test(line)){
              var match = line.match(regex.section);
              value[match[1]] = {};
              section = match[1];
          }else if(line.length == 0 && section){
              section = null;
          };
      });
      return value;
  },
      
    /**
     * Loops thru all language elements and sets the current language text
     * 
     * @param {string} lang
     * @return
     * @api private
     */
    updateElements = function(lang, data) {
      debug('Updating elements with language: ' + lang, data, languageData);

      var missing = [];

      // Select all elements and loop thru them
      $('[data-lang-ckey],[data-lang-tkey],[data-lang-pkey]').each(function () {
        var 
          // <span data-mi18n="C:xxx;T:sss;P:aaa;V:sdsd">...</span> data('mi18n').split(';').split(':')
          $this = $(this),                     // jQuery object of the element
          ckey = $this.attr('data-lang-ckey'), // Key for the content of the element
          tkey = $this.attr('data-lang-tkey'), // Key for title attribute of the element
          pkey = $this.attr('data-lang-pkey'), // Key for placeholder attribute of the element
          vkey = $this.attr('data-lang-vkey'), // Key for value attribute of the element
          cval = deepValue(data, ckey),        // Value of the content
          tval = deepValue(data, tkey),        // Value of the title attribute
          pval = deepValue(data, pkey)         // Value of the placeholder attribute
          pval = deepValue(data, pkey)         // Value of the value attribute
          ;

        // Execute callback and if the result is false run the default action
        if(!options.onItem || 
           !options.onItem.apply(
             null, 
             [lang, 
              { 
               content: { key: ckey, val: cval}, 
               title: {key: tkey, val: tval}, 
               placeholder: { key: pkey, val:pval },
               value: { key: vkey, val:vval }
              }
            ]
            )
          ) {

          // If there is a content key set the content and handle "not found" condition
          if(ckey) {
            if(!cval) missing.push(this);
            $this
            .removeClass(options.notFound)
            .html(cval)
            .addClass( (cval ? undefined : options.notFound ) );
          }          

          // If there is a title key set the title attribute and handle "not found" condition
          if(tkey) {
            if(!tval) missing.push(this);
            $this
            .removeClass(options.notFound)
            .attr('title', (tval || $this.attr('title')) )
            .addClass( (tval ? undefined : options.notFound ) );
          }

          // If there is a placeholder key set the placeholder attribute and handle "not found" condition
          if(pkey) {
            if(!pval) missing.push(this);
            $this
            .removeClass(options.notFound)
            .attr('placeholder', (pval || $this.attr('placeholder')) )
            .addClass( (pval ? undefined : options.notFound ) );
          }

          // If there is a placeholder key set the placeholder attribute and handle "not found" condition
          if(vkey) {
            if(!vval) missing.push(this);
            $this
            .removeClass(options.notFound)
            .attr('value', (vval || $this.attr('value')) )
            .addClass( (vval ? undefined : options.notFound ) );
          }

        }
      });

      if(missing.length) debug('Missing values for elements:', missing);

      if(data) $("html").attr("lang", lang.split('-')[0]);
      options.changed && options.changed.apply(null, [err, lang, data]);
    },

    switchLanguage = function(lang, cb) {

      var 
        data = languageData[lang],
        source = undefined
        ;

      if(!data) {

        if('string' == typeof options.source) {
          debug('Prepare source from string:', options.source);
          source = options.source.replace('{{LANG}}', lang); 
        } else 

        if('function' == typeof options.source) {
          debug('Prepare source by calling:', options.source);
          source = options.source.apply(null, [lang]);
        }

        if(source) {
          debug('Will load language data for "' + lang + '" from source:', source);
          $.ajax({
            type:'GET',
            url: source,
            cache: false,
            success: function(data_) { 
             debug('Received language data:', data_);
             if('string' == typeof data_) {
              languageData[lang] = parseIniString(data_);
             }else {
              languageData[lang] = data_;
             }              
             data = languageData[lang];
             cb && cb.apply(null, [lang, data]);
            },
            error: function(jqXHR, textStatus, errorThrown) {
//              console.log('error in AJAX call...');
//    console.log('jqXHR:', jqXHR);
//    console.log('textStatus:', textStatus);
//    console.log('error:', errorThrown);
              err = explainAjaxError(jqXHR, textStatus, errorThrown);
              cb.apply(null, [lang, data]);
            }
          });
        } else {
          debug('No language data and no source for language:', lang);
          cb && cb.apply(null, [lang, data]);  
        }

      } else {
        cb && cb.apply(null, [lang, data]);
      }
    },

      /**
       * Switch language text on elements
       * 
       * @param {string} lang
       * @return
       * @api private
       */
      language = function(lang) {        
        err = undefined;
        debug('Switching to language: ', lang);
        switchLanguage(lang, updateElements);
      },

      /**
       * Sets configuration values 
       * 
       * @param {object} options_
       * @return
       * @api private
       */
      configure = function(options_) {
        debug('Configuring with: ', options_);
        options = $.extend({}, options, options_);
        languageData = options.data || {};
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
      var lang = $(this).attr('data-lang-switch');
      if(lang) $.fn.miniI18n(lang);
    });
  });
  
}(window, jQuery);
</script>

<script language="javascript" type="text/javascript">
$(function () { 'use strict'

  $.fn.bootstrapChoice = function(options) {    
    var
      defaults = {               
        modal: null
      , onClick: function(choice, button) { return false; }
      , getChoice: function(button) { return $(button).data('choice'); } // Default: return the data-choice attribute value
      , onShow: function() { }
      , onShown: function() { }
      , onHide: function() { }
      , onHidden: function() { }
      }
      ;

    return this.each(function() {
      var 
        settings = $.extend({}, defaults, options)
      , $this = $(this)
      , $modal = $(settings.modal);
        ; 

      if(!settings.modal) alert('No modal set (.modal == null). This is not allowed!');      

      $modal.on('show.bs.modal', function() { settings.onShow.apply(null, [] ); });
      $modal.on('shown.bs.modal', function() { settings.onShown.apply(null, [] ); });
      $modal.on('hide.bs.modal', function() { settings.onHide.apply(null, [] ); });
      $modal.on('hidden.bs.modal', function() { settings.onHidden.apply(null, [] ); });

      $modal.on('click', 'button', function() {          
          var choice = null;
          var closeModal = false;
          if('modal'==$(this).data('bs-dismiss')) return;
          if(settings.getChoice) choice = settings.getChoice.apply(null, [ this ] )
          if(settings.onClick) closeModal = settings.onClick.apply(null, [ choice, this ]);
          if(closeModal) $modal.modal('hide');
      });

      $this.on('click', function() { 
        $modal.modal('show');
      });
      
    });
  }

});
</script>



<script language="javascript" type="text/javascript">
$(function () { 'use strict'
  var
    isSocketExtensionLoaded = <?php echo $isSocketExtensionLoaded; ?>    

  , isDebugEnabled = <?php echo $isDebugEnabled; ?>  

  , baseAddress = '<?php echo $_SERVER['PHP_SELF']; ?>'

  , debugPrint = function(/* args */) {
      if(console && isDebugEnabled) {
        var args = [].slice.call(arguments);
        args.unshift('*** WOL: ');
        console.log.apply(null, args);
      }
    }

  , getAllQueryParameters = function(url) {
      url = url || location.search;
      debugPrint('query parameters:', getAllQueryParameters());
      var
        isArray = function (o) { return ('[object Array]' === Object.prototype.toString.call(o)); },
        params = {}
        ;

      if (url) url.substr(1).split("&").forEach(function (item) {
        var
          s = item.split("="),
          k = decodeURIComponent(s[0]),
          v = s[1] && decodeURIComponent((s[1] + '').replace(/\+/g, '%20'))  //  null-coalescing / short-circuit
          ;
        if (!params.hasOwnProperty(k)) {
          params[k] = v;
        } else {
          if (!isArray(params[k])) params[k] = [params[k]];
          params[k].push(v);
        }
        //        (k in queryParameters) ? queryParameters[k].push(v) : queryParameters[k] = [v]
        //          (queryParameters[k] = queryParameters[k] || []).push(v) // null-coalescing / short-circuit
      })
      return params;
    }

  , showNotification = function(message, style, autoClose) {     
      var $notificationContainer = $('#notificationContainer');
 
      if (!message || ''===message) {
        $notificationContainer.empty();
        return;
      }

      style = style || 'danger';
      autoClose = +autoClose || 0;

      var
        $notification = $([
          '<div class="alert alert-'
        , style
        , ' alert-dismissible fade show" role="alert" >'
        , message
        ,   '<button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close" ></button>',
        , '</div>'
        ].join('')).hide()
        
      , hideNotification = function () {
          $notification.slideUp(400, function () { $notification.remove() });
        }
        ;

      $notificationContainer.prepend($notification);
      $notification
        .fadeIn()
        .find('.close-alert')
        .on('click', hideNotification)
        ;

      if (0 < autoClose) setTimeout(hideNotification, autoClose);
    }

  , renderTemplate = function(html, data, rowCallback) {
      // Minimalistic javascript template engine
      // Use it like: var html = templateEngine('<h1>{{this.title}}</h1><p>{{this.comment}}</p>', { title: 'Welcome', comment: 'Here you can do all nice things.' });
      // Javascript http://krasimirtsonev.com/blog/article/Javascript-template-engine-in-just-20-line
      var
        re = /\{\{([\s\S]+?(\}?)+)\}\}/g, // /\{\{(.+?)\}\}/g,
        reExp = /(^( )?(var|if|for|else|switch|case|break|{|}|;))(.*)?/g,
        code = 'with(obj) { var r=[];\n',
        cursor = 0,
        result = [],
        match
        ;

      var
        isArray = function (o) { return ('[object Array]' === Object.prototype.toString.call(o)); },
        add = function (line, js) {
          js ?
            (code += line.match(reExp) ? line + '\n' : 'r.push(' + line + ');\n') :
            (code += line != '' ?
              'r.push("' + line.replace(/"/g, '\\"') + '");\n' :
              ''
            );
          return add;
        };

      while ((match = re.exec(html))) {
        add(html.slice(cursor, match.index))(match[1], true);
        cursor = match.index + match[0].length;
      }
      add(html.substr(cursor, html.length - cursor));
      code = (code + 'return r.join(""); }').replace(/[\r\t\n]/g, ' ');
      try {
        if (!isArray(data)) data = [data];
        for (var i = 0; i < data.length; i++) {

          var
            item = JSON.parse(JSON.stringify(data[i])),
            ignore = rowCallback && rowCallback.apply(null, [item, i])
            ;
          if (!ignore) result.push(new Function('obj', code).apply(item, [item]));
        }
      }
      catch (err) { console && console.error("'" + err.message + "'", " in \n\nCode:\n", code, "\n"); }
      return result;
    }


  , unsavedChangesCount = 0

  , makeClean = function() {
      unsavedChangesCount = 0;
      updateUi();
    }

  , makeDirty = function() {
      unsavedChangesCount++;
      updateUi();
    }

  , getConfiguration = function() {
      return $('#hostTable tbody tr').map(function() { return $(this).data('wol'); }).get();
    }

  , addHost = function(mac,host,cidr,port,comment) {      
      var
        hostConfig = {
          mac: mac
        , host: host
        , cidr: cidr
        , port: port
        , comment: comment
        }
      , jsonConfig = JSON.stringify(hostConfig);
        ;

      hostConfig['dataWol'] = jsonConfig;
      var tr = renderTemplate($('#tableRowTemplate').html(), hostConfig);
      $('#hostTable tbody').append(tr);
    }

  , saveConfigToServer = function() {
      var wolConfig = $('#hostTable tbody tr').map(function() { return $(this).data('wol'); }).get();

      $.ajax({
        url: baseAddress + '?aop=CONFIG.SET' + (isDebugEnabled ? '&debug=1' : '')
      , type: 'POST'
      , data: JSON.stringify(getConfiguration())
      , contentType: 'application/json; charset=utf-8'
      , dataType: 'json'
      , beforeSend: function(/* xhr */) { $('#ajaxLoader').fadeIn(); }
      , complete: function(result) { $('#ajaxLoader').fadeOut(); }
      , error: function(jqXHR, textStatus, errorThrown ) { showNotification('<small>Error ' + jqXHR.status + ' calling "' + baseAddress + '": ' + jqXHR.statusText + '<hr>' + jqXHR.responseText + '</small>', 'danger', 10000); }
      , success: function(resp) {
          if('string' == typeof resp) {
            showNotification(resp);
          } else {
            makeClean();
            showNotification($('#textConfigSavedSucessfully').html(), 'success', 3000);
          }
        }
      });
    }

  , loadConfigFromServer = function(doNotMakeClean) {
      $.ajax({
        url: baseAddress
      , type: 'GET'
      , data: { debug: isDebugEnabled, aop: 'CONFIG.GET' }
      , beforeSend: function(/* xhr */) { $('#ajaxLoader').fadeIn(); }
      , complete: function(result) { $('#ajaxLoader').fadeOut(); }
      , error: function(jqXHR, textStatus, errorThrown ) { showNotification('<small>Error ' + jqXHR.status + ' calling "' + baseAddress + '": ' + jqXHR.statusText + '<hr>' + jqXHR.responseText + '</small>', 'danger', 10000); }
      , success: function(resp) {
          if('string' == typeof resp) {
            showNotification(resp);
          } else {
            for(var i=0; i<resp.length; i++) {
              addHost(resp[i].mac, resp[i].host, resp[i].cidr, resp[i].port, resp[i].comment);
            }
            if(!doNotMakeClean) makeClean();
          }
        }
      });
    }

  , updateUi = function() {
      if(unsavedChangesCount) {
        $('#pageContainer').addClass('unsaved-changes') 
      } else {
        $('#pageContainer').removeClass('unsaved-changes') 
      }
    }

  , lastUpdateIndex = 0
  , checkNextHostState = function() {

      var
        $tr = $('#hostTable tbody tr:nth-child(' + (++lastUpdateIndex) + ')')
      , $i = $tr.find('td:first-child >') // i element of the first TR child
      , wolInfo = $tr.data('wol') || { }
        ;

      if(0==$tr.length) {
        lastUpdateIndex = 0;
        setTimeout(checkNextHostState, 10);
      } else {
        $.ajax({
          url: baseAddress
        , type: 'GET'
        , data: { debug: isDebugEnabled, aop: 'HOST.CHECK', host:wolInfo.host }
        , beforeSend: function(/* xhr */) { 
            $i
              .removeClass('fa-question fa-eye fa-thumbs-up fa-thumbs-down text-danger text-success')
              .addClass('fa-eye text-muted')
              ;
          }
        , complete: function(result) { setTimeout(checkNextHostState, 2000); }
        , error: function(jqXHR, textStatus, errorThrown ) { showNotification('<small>Error ' + jqXHR.status + ' calling "' + baseAddress + '": ' + jqXHR.statusText + '<hr>' + jqXHR.responseText + '</small>', 'danger', 10000); }
        , success: function(resp) {
            if('string' === typeof resp) { resp = { error: resp }; }
            if(resp && resp.error && resp.error !== '') {
              return showNotification(resp.error, 'danger', 7000);
            } else {
              $i.attr('title', resp.info);
              if(resp.isUp) {
                  $i
                  .removeClass('fa-eye text-muted')
                  .addClass('fa-thumbs-up text-success')
                  ;
                } else {
                  $i
                  .removeClass('fa-eye text-muted')
                  .addClass('fa-thumbs-down text-danger')
                ;
              } 
            }
          }
        });
      }
    }
    ;
		


  /**
   * Event Handler
   */
  $('#saveConfigToServer').on('click', function(evt) {
    setTimeout(saveConfigToServer, 10);
  })

  $('#loadConfigFromServer').bootstrapChoice({ 
    modal: '#chooseLoadConfigModal'
  , onClick: function(choice) {
      var rowCount = $('#hostTable tbody tr').length;
      if('REPLACE' == choice) { $('#hostTable tbody').empty(); rowCount = 0; }
      if(rowCount != 0) makeDirty();
      loadConfigFromServer((rowCount != 0));
      return true;
    }   
  });  

  $('#exportModal').on('show.bs.modal', function() {
    $('#exportJson').val(JSON.stringify(getConfiguration()));
  });

  $('#importJsonConfig').on('click', function() {
    var
      rowCount = $('#hostTable tbody tr').length
    , jsonString = $('#importJson').val()
    , overwrite = $('#importJsonOverwriteExisting:checked').length
    , config = []
      ;

    $('#importErrorContainer').empty();

    try {
      config = JSON.parse(jsonString);
    }
    catch(err) {
      $('#importJsonErrorContainer').append([
          '<div class="alert alert-danger alert-dismissible fade show" role="alert" >'
        , err
        ,   '<button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close" ></button>',
        , '</div>'
      ].join());
      return;
    }

    if(overwrite) { $('#hostTable tbody').empty(); }
    makeDirty();
    for(var i=0; i<config.length; i++) {
      addHost(config[i].mac, config[i].host, config[i].cidr, config[i].port, config[i].comment);
    }
    $('#importModal').modal('hide');
  });

  $('#hostTable tbody').on('click', '.btnRemoveHost', function(event) {
		event.preventDefault();
		var 
      $tr = $(this).closest('tr')
    , wolData = $tr.data('wol')
      ;

		$('#mac').val(wolData.mac);
		$('#host').val(wolData.host);
		$('#cidr').val(wolData.cidr);
		$('#port').val(wolData.port);
		$('#comment').val(wolData.comment);
    $tr.remove();
    makeDirty();
		return false;
  })

  $('#hostTable tbody').on('click', '.btnWakeUpHost', function() {
		event.preventDefault();
		var 
      $tr = $(this).closest('tr')
    , wolData = $tr.data('wol')
      ;

    wolData['debug'] = isDebugEnabled;
    wolData['aop'] = 'HOST.WAKEUP';

      $.ajax({
        url: baseAddress
      , type: 'GET'
      , data: wolData
      , beforeSend: function(/* xhr */) { $('#ajaxLoader').fadeIn(); }
      , complete: function(result) { $('#ajaxLoader').fadeOut(); }
      , error: function(jqXHR, textStatus, errorThrown ) { showNotification('<small>Error ' + jqXHR.status + ' calling "' + baseAddress + '": ' + jqXHR.statusText + '<hr>' + jqXHR.responseText + '</small>', 'danger', 10000); }
      , success: function(resp) {
          if('string' == typeof resp) {
            showNotification(resp);
          } else {
            showNotification(resp['info'], 'success', 5000);
          }
        }
      });


		return false;
  })

  $('#addHost').on('click', function(evt) {

    var
      mac = $('#mac').val()
    , host = $('#host').val()
    , cidr = $('#cidr').val()
    , port = $('#port').val()
    , comment = $('#comment').val()
    , msg = ''
      ;

    if(''==mac) msg = msg + '<br/>The <strong>mac-address</strong> field must not be empty.'
    if(''==host) msg = msg + '<br/>The <strong>host</strong> field must not be empty.'
    if(''==cidr) msg = msg + '<br/>The <strong>cidr</strong> field must not be empty.'
    if(''==port) msg = msg + '<br/>The <strong>port</strong> field must not be empty.'

    if(msg) {
      showNotification('Please check your input:' + msg, 'warning', 10000);
      return;
    }

    addHost(mac,host,cidr,port,comment);
    makeDirty();
  });

  /**
   * initialize language switching support
   */
  $.fn.miniI18n({
    debug: false
  , data: {
     'en-US': {
        'title': 'Wake On Lan'
      , 'tools': 'Tools'
      , 'download_config': 'Download Configuration'
      , 'export_config': 'Export Configuration'
      , 'import_config': 'Import Configuration'
      , 'load_config': 'Load Configuration'
      , 'save_config': 'Save Configuration'
      , 'mac_address': 'MAC-Address'
      , 'p_mac_address': 'Mac-Address here'
      , 'ip_or_hostname': 'IP or Hostname'
      , 'p_ip_or_hostname': 'IP or Hostname here'
      , 'subnet': 'Subnet Size (CIDR)'
      , 'p_subnet': 'Subnet Size (CIDR) here'
      , 'port': 'Port'
      , 'p_port': 'Port here'
      , 'comment': 'Comment'
      , 'p_comment': 'Comment here'

      , 'c_load_configuration': 'Load Configuration'
      , 'c_replace_config': ''
      , 'c_append_config': ''
      }
    , 'de-DE': {
        'title': 'Wake On Lan'
      , 'tools': 'Werkzeuge'
      , 'download_config': 'Konfiguration herunterladen'
      , 'export_config': 'Konfiguration exportieren'
      , 'import_config': 'Konfiguration Importieren'
      , 'load_config': 'Konfiguration laden'
      , 'save_config': 'Konfiguration speichern'
      , 'mac_address': 'MAC-Addresse'
      , 'p_mac_address': 'Mac-Addresse hier'
      , 'ip_or_hostname': 'IP oder Hostname'
      , 'p_ip_or_hostname': 'IP oder Hostname hier'
      , 'subnet': 'Subnet Größe (CIDR)'
      , 'p_subnet': 'Subnet Größe (CIDR) hier'
      , 'port': 'Port'
      , 'p_port': 'Port hier'
      , 'comment': 'Bemerkung'
      , 'p_comment': 'Bemerkung hier'
      }
    , 'es-ES': {
        'title': 'Wake On Lan'
      , 'tools': 'Instrumentos'
      , 'download_config': 'Descargar configuración'
      , 'export_config': 'Exportar configuración'
      , 'import_config': 'Importar configuración'
      , 'load_config': 'Cargar configuración'
      , 'save_config': 'Guardar configuración'
      , 'mac_address': 'MAC-Dirección'
      , 'p_mac_address': 'Mac-Dirección aquí'
      , 'ip_or_hostname': 'IP o nombre de host'
      , 'p_ip_or_hostname': 'IP o nombre de host aquí'
      , 'subnet': 'Tamaño de subred (CIDR)'
      , 'p_subnet': 'Tamaño de subred(CIDR) aquí'
      , 'port': 'Puerto'
      , 'p_port': 'Puerto aquí'
      , 'comment': 'Comentario'
      , 'p_comment': 'Comentario aquí'
      }
    }
  });

  // Initialize tooltips overall
  var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'))
  var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
    return new bootstrap.Tooltip(tooltipTriggerEl)
   });

  /** 
   * Enable sorting the table rows with drag&drop
   */
  $("#hostTable tbody").sortable({
    helper: function(e, tr) {
		  var $originals = tr.children();
		  var $helper = tr.clone();
		  $helper.children().each(function(index) {
		    $(this).width($originals.eq(index).width())
		  });
		  return $helper;
  	}
  , items: 'tr'
  , opacity: 0.9
  , stop: function(event, ui) { makeDirty(); }
  }).disableSelection();

  $(window).on('beforeunload', function(event) {
    if(!unsavedChangesCount) return;
    var confirmationMessage = $('#unsavedChangesConfirmation').text();
    var confirmationMessage = 'It looks like you have been editing something. '
                            + 'If you leave before saving, your changes will be lost.';
    (event || window.event).returnValue = confirmationMessage; //Gecko + IE
    return confirmationMessage; //Gecko + Webkit, Safari, Chrome etc.
  });

  // Show warning if the sockets extension is not available in php
  if(!isSocketExtensionLoaded) showNotification( $('#textNoSocketExtensionLoaded').html(), 'warning' );

  // Finally load the configuration from the server 
  setTimeout(loadConfigFromServer, 10);

  // Start updating the host state
  setTimeout(checkNextHostState, 1000);

});
</script>      
  </body>
</html>
