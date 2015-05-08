<?php

$ch = curl_init();

curl_setopt($ch, CURLOPT_URL, "http://maps.googleapis.com/maps/api/distancematrix/json?origins=16.0544066,108.2021666&destinations=16.4498,107.5623501");
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);

// execute the request
$result = curl_exec($ch);

// close curl resource to free up system resources
curl_close($ch);
$result = json_decode($result, true);
$result = $result['rows'][0]['elements'][0]['distance']['value'];

echo $result;

?>