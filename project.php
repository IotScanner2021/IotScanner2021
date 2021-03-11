<?php
	$ip = $_GET['ip'];
	#$ip = "140.123.0.0/16";
	$count = 5;
	$filename = "project.txt";
	
	//$url = "http://7dee16c23e43.ngrok.io/ccuproj/home.html";
	//$command = "python ./api/main.py --ip ".$ip." --count ".$count." > ".$filename;
	$command = "python ./api/main.py --ip ".$ip." --count ".$count;
	echo shell_exec($command);
		
	/*
	$command = "python ./api/main.py --ip ".$ip." --count ".$count;
	$str = shell_exec($command);
	$filepath = "/usr/share/nginx/html/ccuproj/project.txt";
	$f = fopen($filepath,"w+");
	fwrite($f,$str);
	fclose($f);
	 */
		
	sleep(2);
?>
