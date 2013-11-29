#!/usr/bin/php
<?php
/*****************************************************************************************
***************** C O N F I G ***********************
*/
define('DEBUG',true);
define('POSTURL','http://zenbench.znx.fr/runs');
$CONF_COLLECT = array(
 //'STAT => 'CMD'
	'&HOSTNAME&'=>'hostname -f',
	'CPU_LOAD' => "cat /proc/loadavg |awk '{print $1}'",
	'CPU_TYPE'=>'cat /proc/cpuinfo  |grep "model name"|cut -d ":" -f 2|head -n 1',
	'CPU_MHZ'=>'cat /proc/cpuinfo  |grep "cpu MHz" |cut -d ":" -f 2 |head -n 1',
	'CPU_MHZ_2'=>'dmidecode -s processor-frequency|head -n 1',
	'CPU_NB'=>'cat /proc/cpuinfo  |grep "^processor"|wc -l',
	'CPU_CACHE'=>'cat /proc/cpuinfo  |grep "cache size" |cut -d ":" -f 2|head -n 1',
	'RAM_TOTAL'=>'free -h |grep "^Mem:" |awk \'{print $2}\'',
	'RAM_FREE'=>'free -m |grep "\-/+ buffers/cache"|awk \'{print $4}\'',
	'RAM_NBDIM'=>'dmidecode -t memory |grep "Locator: DIM" |wc -l',
	'RAM_TYPE'=>'dmidecode --type 17 |grep Type: |cut -d ":" -f 2 |head -n 1',
	'RAM_FREQ'=>'dmidecode --type 17 |grep Speed: |cut -d ":" -f 2 |sort -nk1 |head -n 1'
);

debug("1 - Collect data on machine");
$infosystem=collectstat($CONF_COLLECT);
$NB_CPU=$infosystem['CPU_NB'];
$PWD=getcwd();

$CONF_ROUTINE = array(
//	'CPU_SHA256' => '/root/zenbench_infosrv/zenbench_go_cpu_mono_sha256 -o #OUTPUT#'
	'CPU_WPAPSK_JOHN'=>$PWD.'/john-1.7.2-bp17-mpi8/run.sh '.intval(1 + $NB_CPU * 2).' #OUTPUT#'
);

$JSON_TEMPLATE='{
  "id": "&USER_EMAIL&",
  "host": "&HOSTNAME&",
  "env": [
    { "types": "cpu", "ref": "&CPU_REF&" &CPU_DIVERS&},
    { "types": "ram", "ref": "&RAM_REF&" &RAM_DIVERS&}
  ],
  "metrics": [
	&RESULTATS&
  ]
}';

/*********************************************************************
************* MAIN *****************
*/
debug($infosystem);
debug("2 - Run benchmarks ");
$result=run_routines($CONF_ROUTINE);
debug("3 - PostData");
$json=make_json($JSON_TEMPLATE,$infosystem,$result);
debug($json);
post_data(POSTURL,$json);
/*******************************************************************
******** F U N C T I O N S
*/
function post_data($url,$json){
	//curl ici
        $CMD="curl -XPOST '".$url."' -H 'Content-type: application/json' --data-binary '".$json."'";
	echo $CMD;
	debug(exec($CMD));
}
function make_json($j,$sys,$result){
	$CPU_DIVERS='';
	$RAM_DIVERS='';
	foreach($sys as $k=>$v){
		$tmp=', "'.$k.'": "'.$v.'"';
		if(preg_match('#^RAM_#',$k)){
			$RAM_DIVERS .=$tmp;
		}elseif(preg_match('#^CPU_#',$k)){
			$CPU_DIVERS .=$tmp;
		}
	}
	$j=str_replace('&USER_EMAIL&','v1@anonyme',$j);
	$j=str_replace('&HOSTNAME&',$sys['&HOSTNAME&'],$j);
	$j=str_replace('&CPU_REF&',$sys['CPU_TYPE'],$j);
	$j=str_replace('&CPU_DIVERS&',$CPU_DIVERS,$j);
	$j=str_replace('&RAM_DIVERS&',$RAM_DIVERS,$j);
	$j=str_replace('&RAM_REF&',$sys['RAM_TYPE']."-".$sys['RAM_FREQ']."-".$sys['RAM_TOTAL'],$j);

//{ "id": "test1", "value": "255666"}		
	$js_r='';
	$first=true;
	foreach($result as $k=>$v){
		if(!$first){
			$js_r .=', ';
		}
		$js_r.='{ "id": "'.$k.'", "value": "'.$v.'"}'."\n";	
		$first=false;
	}
	$j=str_replace('&RESULTATS&',$js_r,$j);
	return($j);
}
function run_routines($routine){
	$result=array();
	foreach($routine as $k=>$c){
		$r=0;
		$file=mktmp();
		$c=str_replace('#OUTPUT#',$file,$c);
		debug("Execute : $c");
		debug(exec($c));
		if(file_exists($file)){
			$r=intval(extract_result($file));
			rmtmp($file);
			$result[$k]=intval($r);
		}		
	}
	return ($result);
}
function extract_result($file){
	return(exec('cat '.$file.' |head -n 1'));
}
function rmtmp($tmp){
	unlink($tmp);
}
function mktmp(){
	return exec('mktemp');
}
function addqq($s){
	return '"'.$s.'"';
}
function collectstat($arr){
	$r=array();
	foreach ($arr as $k=>$c){
		debug( "\t $k, run : $c");
		$r[$k]=trim(exec($c));
	}
	return($r);
}
function debug($s){
	if(DEBUG){
		if(is_array($s)){
			print_r($s);
		}else{
			echo $s."\n";
		}
	}
}
