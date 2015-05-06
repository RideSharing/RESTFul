<?php

$handle = fopen("include/log.txt", "a");
        fwrite($handle, "text");
        fwrite($handle, "\r\n");
        fclose($handle);

?>