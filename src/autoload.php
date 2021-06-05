<?php

function ocsp_requestor_autoload( $classname )
{
	$prefix = 'Ocsp\\';
	if ( strpos( $classname, $prefix ) !== 0 ) return false;
	$filename = substr( $classname, strlen( $prefix ) ) . '.php';
	// $filename = "$classname.php";
	require_once  __DIR__ . "/$filename" ;
}

spl_autoload_register( 'ocsp_requestor_autoload' );
