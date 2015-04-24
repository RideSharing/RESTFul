<?php

require_once 'include/PassHash.php';

echo PassHash::hash($_GET['p']);

?>