<?php

$api_key = "	ce657571fcbe01921ce838df4cccddf4";

$ch = curl_init();

curl_setopt($ch, CURLOPT_URL, "localhost/RESTFul/v1/itineraries?start_address_lat=16.0644068&start_address_long=108.2121667&end_address_lat=16.4498&end_address_long=107.5623501");
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
curl_setopt($ch, CURLOPT_HTTPHEADER,array('Authorization: '.$api_key));

// execute the request
$result = curl_exec($ch);

// close curl resource to free up system resources
curl_close($ch);
$iti = json_decode($result, true);

print_r($iti);

?>