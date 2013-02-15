<?php
/*
# frw.conf Format:
# # starts comment (single on a line)
# variables section:
# VARS {
# VARNAME="VALUE"
# along those there are:
# INPUT="policy" (default DROP)
# OUTPUT="policy" (default DROP)
# FORWARD="policy" (default ACCEPT)
# IPTABLES="/path/to/iptables/executable" (default /sbin/iptables)
# }
# then rules follow (tab-delimited list):
# RULES {
# CHAIN\tIF\tPROTO\tSUBPROTO\tSRCIP\tSRCPORT\tDSTIP\tDSTPORT\tSYN\tDOLOG\tRESULT\tCOMMENT
# where
#   CHAIN = INPUT/OUTPUT/FORWARD/(NAT?) (default INPUT)
#   IF = eth0 etc, can be var from VARS (default eth0)
#   PROTO = tcp/udp (default tcp)
#   SUBPROTO = protocol subtype (useful for ICMP messages)
#   SRCIP = source IP address(range), can be var from VARS
#   SRCPORT = source port(range), can be VAR or service name from /etc/services
#   DSTIP = target IP... ditto
#   DSTPORT = target port...
#   SYN = Y if syn is reqd (means "Initiating connection") -- to be replaced
#         N = !--syn
#         I = ignore
#         with all --tcp-flags (default I)
#   DOLOG = Y if logging is reqd (default N)
#   RESULT = ACCEPT, REJECT, DENY, DROP (default DENY)
# }

COULDDO: XML-formatted frw.conf?
*/
//error_reporting(0);
session_start();

$rulerules = array(
    'chain'    => array('prefix'=>' -A','type'=>'text'), // INPUT/OUTPUT
    'if'       => array('prefix'=>' -i','type'=>'var'),  // $EXTIF
    'proto'    => array('prefix'=>' -p','type'=>'text'), // tcp/udp
    'subproto' => array('prefix'=>'','type'=>'text'),    // 0-xx follows proto
    'src'      => array('prefix'=>' -s','type'=>'var'),
    'srcport'  => array('prefix'=>' --sport','type'=>'service'),
    'dst'      => array('prefix'=>' -d','type'=>'var'),
    'dstport'  => array('prefix'=>' --dport','type'=>'service'),
    'syn'      => array('prefixN'=>' -m state --state RELATED,ESTABLISHED','prefixY'=>' -m state --state INVALID','type'=>'flag'),
    'log'      => array('prefixY'=>' --log-level debug','prefixN'=>'','type'=>'flag'),
    'result'   => array('prefix'=>' -j','type'=>'text'),
    'comment'  => array('prefix'=>' #','type'=>'text')
);

define("CONFIGFILE", "frw.conf");
define("DUMPFILE", "rc.firewall");

function dump_var($v)
{
	echo "<pre>";var_dump($v);echo "</pre>";
}


function redirect($url)
{
    ob_end_clean();
    header('Location: '.$url);
    exit;
}

function go_home()
{
    redirect($_SERVER['PHP_SELF']);
}

/** FILE IO / LOADSAVE RULES ********************************************/

function init_defaults()
{
    $_SESSION['vars']['IPTABLES'] = "/sbin/iptables";
    $_SESSION['vars']['INPUT'] = "DROP";
    $_SESSION['vars']['OUTPUT'] = "DROP";
    $_SESSION['vars']['FORWARD'] = "ACCEPT";
}

function load_services()
{
    $serv = file("/etc/services");
    
    foreach ($serv as $s) {
	if (substr($s,0,1) == '#') continue;
	$service = preg_split('/[ \t]/', $s, 3, PREG_SPLIT_NO_EMPTY);
	
	if (count($service) >= 2)
	{
	    list($port,$proto) = explode('/',$service[1]);
	    $proto = trim($proto);
	    $_SESSION['services'][] = array('name'=>$service[0],'port'=>$port,'proto'=>$proto);
	}
    }
}

function load_config()
{
    $conf = file(CONFIGFILE);
    $conf = implode('',$conf);

    // Get VARS block
    if (preg_match("/VARS\s*{((.|\n)*?)}/",$conf,$vars)) {
	$vars = trim($vars[1]);
	$vars = explode("\n", $vars);

        // parse VARS

	foreach ($vars as $v) {
	    $var = explode("=", $v);

	    $var[0] = trim($var[0]);
	    $var[1] = trim($var[1]);
	    
	    if (substr($var[1],0,1) == '"') $var[1] = substr($var[1],1,strlen($var[1])-2);
	    $_SESSION['vars'][$var[0]] = $var[1];
	}
    }
    
    // Get RULES block
    if (preg_match("/RULES\s*{((.|\n)*?)}/",$conf,$rules)) {
	$rules = trim($rules[1]);
	$rules = explode("\n", $rules);

        // parse RULES

	foreach ($rules as $r) {
	    if (substr($r,0,1) == '#') continue;
	    $r = ltrim($r); // strip only starting whitespace
	    $rule = explode("\t", $r);
	    
	    if (count($rule)==12) {
		$_SESSION['rules'][] = array(
		    'chain'=>$rule[0],
		    'if'=>$rule[1],
		    'proto'=>$rule[2],
		    'subproto'=>$rule[3],
		    'src'=>$rule[4],
		    'srcport'=>$rule[5],
		    'dst'=>$rule[6],
		    'dstport'=>$rule[7],
		    'syn'=>$rule[8],
		    'log'=>$rule[9],
		    'result'=>$rule[10],
		    'comment'=>$rule[11]
		);
	    }
	}
    }
}

/** CONFIG SAVER *********************************************************/

function save_config()
{
    // TODO: keep user comments for each rule/ruleset
    // TODO: will need 'ruleset' support...
    // TODO: for iptables will need 'state' support?
    
    $out = fopen(CONFIGFILE.".tmp", "w");
    
    if (!$out) {
	echo 'Error saving configuration. Check that you have write permissions.<br/>';
        echo 'Press <a href="'.$_SERVER['PHP_SELF'].'">here</a> to go back.';
	exit;	
    }
    
    // save VARS
    if ($_SESSION['vars']) {
        fwrite($out, "VARS {\n");
	foreach ($_SESSION['vars'] as $k => $val) {
	    fwrite($out, "\t".$k.'="'.$val."\"\n");
        }
	fwrite($out, "}\n\n");
    } else {
	echo 'WARNING: no variables defined!<br/>';
    }
    // save RULES
    if ($_SESSION['rules']) {
        fwrite($out, "RULES {\n");
        foreach ($_SESSION['rules'] as $k => $rule) {
	    fwrite($out, "\t".$rule['chain'].
		         "\t".$rule['if'].
			 "\t".$rule['proto'].
			 "\t".$rule['subproto'].
			 "\t".$rule['src'].
			 "\t".$rule['srcport'].
			 "\t".$rule['dst'].
		         "\t".$rule['dstport'].
			 "\t".$rule['syn'].
			 "\t".$rule['log'].
			 "\t".$rule['result'].
			 "\t".$rule['comment']."\n");
	}
	fwrite($out, "}\n\n");
    } else {
	echo 'WARNING: no rules defined!<br/>';
    }
    fclose($out);
    rename(CONFIGFILE.'.tmp', CONFIGFILE);
}

/** CONFIG DUMPER *********************************************************/

// A function object
class SimpleFilter 
{
    var $value;
    function SimpleFilter($value) { $this->value = $value; }
    function doFilter($a) { return $a['name'] == $this->value; }
};

function is_var($name)
{
    return in_array($name,array_keys($_SESSION['vars'])) ? true : false;
}

function rule_part($rule, $part)
{
    global $rulerules;

    $rrule = $rulerules[$part];
    $value = $rule[$part];

    $prefix = $rrule['prefix'];
    $type = $rrule['type'];

    if ($type == 'flag') {
	if ($value == 'I') return ''; // Ignore
	if ($value == 'Y') return $rrule['prefixY'];
	if ($value == 'N') return $rrule['prefixN'];
	echo "WARNING: bad flag value ($value) for $part<br/>";
    }
    
    if ($type == 'service') {
	if (!$value) return '';
    
	if (is_numeric($value)) { // numeric port - leave as is
	    return $prefix.' '.$value;
	}
	// variable
	if (is_var($value)) {
	    return $prefix.' $'.$value;
	}
	// port range
	if (strstr($value,':')) {
	    list($left,$right) = explode(':', $value);
	    if (!is_numeric($left))
		if (is_var($left))
		    $left = '$'.$left;
	    if (!is_numeric($right))
		if (is_var($right))
		    $right = '$'.$right;
	    return $prefix.' '.$left.':'.$right;
	}
	
	// named service
	$filt = new SimpleFilter($value);
	$serv = array_filter($_SESSION['services'], array($filt,'doFilter'));
	if (!$serv) // shouldn't happen if edited within interface
	    echo 'WARNING: unknown service name '.$value.'<br/>';
	return $prefix.' '.$value;
    }
    
    if ($type == 'var') {
	if (!$value) return '';

	// UGLY HACK #1
	if ($rule['chain'] == 'OUTPUT' && $part == 'if')
	    $prefix = ' -o';
	// END OF UGLY HACK #1
	
	if (is_var($value)) {
	    return $prefix.' $'.$value;
	}
	echo 'WARNING: no such var '.$value.'<br/>';
	return '';
    }

    // type == 'text':    
    if (!$value) return ''; // don't specify empty text
    return $prefix.' '.$value;
}

function dump_config()
{
    $out = fopen(DUMPFILE.".tmp", "w");
    
    if (!$out) {
	echo 'Error dumping configuration. Check that you have write permissions.<br/>';
        echo 'Press <a href="'.$_SERVER['PHP_SELF'].'">here</a> to go back.';
	exit;	
    }

    fwrite($out, '#!/bin/sh'."\n\n");
    fwrite($out, "## Module loading\n".
                 "/sbin/depmod -a\n".
		 "# Required modules\n".
		 "# Not required modules\n".
		 "/sbin/modprobe ipt_REJECT\n");

    // save VARS
    $skipvars = array('INPUT','OUTPUT','FORWARD');
    
    if ($_SESSION['vars']) {
	foreach ($_SESSION['vars'] as $k => $val) {
	    if (in_array($k,$skipvars)) continue;
	    fwrite($out, $k.'="'.$val.'"'."\n");
        }
	fwrite($out, "\n");
    } else {
	echo 'WARNING: no variables defined!<br/>';
    }

    // save pre-RULES
    fwrite($out, '$IPTABLES -F'."\n\n");
    fwrite($out, '$IPTABLES -P INPUT   '.$_SESSION['vars']['INPUT']."\n");
    fwrite($out, '$IPTABLES -P OUTPUT  '.$_SESSION['vars']['OUTPUT']."\n");
    fwrite($out, '$IPTABLES -P FORWARD '.$_SESSION['vars']['FORWARD']."\n\n");
        
    // save RULES
    if ($_SESSION['rules']) {
        foreach ($_SESSION['rules'] as $k => $rule) {
	    fwrite($out, '$IPTABLES'.
	                 rule_part($rule,'chain').
	                 rule_part($rule,'if').
			 rule_part($rule,'proto').
			 rule_part($rule,'subproto').
			 rule_part($rule,'src').
			 rule_part($rule,'srcport').
			 rule_part($rule,'dst').
			 rule_part($rule,'dstport').
			 rule_part($rule,'syn').
			 rule_part($rule,'result').
			 rule_part($rule,'log').
			 rule_part($rule,'comment')."\n");
	}
	fwrite($out, "\n");
    } else {
	echo 'WARNING: no rules defined!<br/>';
    }
    fclose($out);
    rename(DUMPFILE.'.tmp', DUMPFILE);
    chmod(DUMPFILE, 0755);
}

/** HTML IO ****************************************************/

function html_header()
{
    echo '<html><head>';
    echo '<meta http-equiv="Content-Type" content="text/html; charset=utf8">';
    echo '<title>Firewall Config Tool</title></head><body>';
}

function html_footer()
{
    echo '</body></html>';
}

function html_quotes($str)
{
    return str_replace('"', '&quot;', $str);
}

/** USER IF ****************************************************/

function list_rules()
{
    echo 'Current firewall configuration';
    echo '<table border="1" bgcolor="#eeeeee">';
    echo '<tr><th>Chain</th><th>Interface</th><th>Protocol</th><th>Protocol subtype</th><th rowspan="3" colspan="4">Edit</th></tr>';
    echo '<tr><th>Source</th><th>Source port</th>';
    echo '<th>Destination</th><th>Destination port</th></tr>';
    echo '<tr><th>SYN</th><th>Log?</th><th>Result</th></tr>';

    $last = count($_SESSION['rules'])-1;
    $index = 0;
    
    foreach ($_SESSION['rules'] as $k => $rule) {
	echo '<tr bgcolor="'.(($index % 2) ? '#eeeeee':'#ffffff').'">';
	echo '<td colspan="4">'.$rule['comment'].'&nbsp;</td>';
	if ($index > 0)
    	    echo '<td rowspan="4"><a href="'.$_SERVER['PHP_SELF'].'?a=ruleup&i='.$k.'">up</a></td>';
	else
	    echo '<td rowspan="4">&nbsp;</td>';
	if ($index < $last)
    	    echo '<td rowspan="4"><a href="'.$_SERVER['PHP_SELF'].'?a=ruledown&i='.$k.'">down</a></td>';
	else
	    echo '<td rowspan="4">&nbsp;</td>';
	echo '<td rowspan="4"><a href="'.$_SERVER['PHP_SELF'].'?a=edit&i='.$k.'">Правка</a></td>';
	echo '<td rowspan="4"><a href="'.$_SERVER['PHP_SELF'].'?a=drop&i='.$k.'">Удалить</a></td>';
	echo '</tr>';
	
	echo '<tr bgcolor="'.(($index % 2) ? '#eeeeee':'#ffffff').'">';
	echo '<td>'.$rule['chain'].'&nbsp;</td>';
	echo '<td>'.$rule['if'].'&nbsp;</td>';
	echo '<td>'.$rule['proto'].'&nbsp;</td>';
	echo '<td>'.$rule['subproto'].'&nbsp;</td>';
	echo '</tr>';
	
	echo '<tr bgcolor="'.(($index % 2) ? '#eeeeee':'#ffffff').'">';
	echo '<td>'.$rule['src'].'&nbsp;</td>';
	echo '<td>'.$rule['srcport'].'&nbsp;</td>';
	echo '<td>'.$rule['dst'].'&nbsp;</td>';
	echo '<td>'.$rule['dstport'].'&nbsp;</td>';
	echo '</tr>';

	echo '<tr bgcolor="'.(($index % 2) ? '#eeeeee':'#ffffff').'">';
	echo '<td>'.$rule['syn'].'&nbsp;</td>';
	echo '<td>'.$rule['log'].'&nbsp;</td>';
	echo '<td>'.$rule['result'].'&nbsp;</td>';
	echo '</tr>';
	$index++;
    }
    
    echo '<tr><td colspan="4">&nbsp;</td><td colspan="4"><a href="'.$_SERVER['PHP_SELF'].'?a=add">Добавить</a></td></tr>';
    
    echo '</table>';
    
    echo '<div align="center">';
    echo '<table>';
    echo '<tr><td>WARNING: deleting rules without question</td></tr>';
    echo '</table>';
    echo '</div>';

    echo '<div align="right">';
    echo '<table>';
    echo '<tr><td><a href="'.$_SERVER['PHP_SELF'].'?a=dump">Сделать дамп в формате rc.firewall</a></td></tr>';
    echo '</table>';
    echo '</div>';
}

function list_vars()
{
    echo 'Defined variables';
    echo '<table border="1" bgcolor="#eeeeee">';
    echo '<tr><th>Name</th><th>Value</th><th>Edit</th></tr>';

    foreach ($_SESSION['vars'] as $k => $val) {
	echo '<tr>';
	echo '<td>'.$k.'</td>';
	echo '<td>'.$val.'</td>';
	echo '<td><a href="'.$_SERVER['PHP_SELF'].'?a=editvar&i='.urlencode($k).'">Править</a></td>';
	echo '<td><a href="'.$_SERVER['PHP_SELF'].'?a=dropvar&i='.urlencode($k).'">Удалить</a></td>';
	echo '</tr>';
    }

    echo '<tr><td colspan="2">&nbsp;</td><td colspan="2"><a href="'.$_SERVER['PHP_SELF'].'?a=addvar">Добавить</a></td></tr>';

    echo '</table>';

    echo '<div align="center">';
    echo '<table>';
    echo '<tr><td>WARNING: deleting variables without question</td></tr>';
    echo '</table>';
    echo '</div>';

    echo '<div align="right">';
    echo '<table>';
    echo '<tr><td><a href="'.$_SERVER['PHP_SELF'].'?a=reset">Перечитать конфигурацию с диска</a></td>';
    echo '<td><a href="'.$_SERVER['PHP_SELF'].'?a=save">Сохранить конфигурацию на диске</a></td></tr>';
    echo '</table>';
    echo '</div>';
}

function service_names()
{
    $out = array();
    foreach ($_SESSION['services'] as $v) {
	$out[] = $v['name'];
    }
    $out = array_unique($out);
    return $out;
}

function txt_select($name, $txt, $def)
{
    echo '<select name="'.$name.'">';
    echo '<option value=""></option>';
    foreach ($txt as $val) {
	echo '<option value="'.html_quotes($val).'"';
	if ($def == $val) echo ' selected';
	echo '>'.html_quotes($val).'</option>';
    }
    echo '</select>';
}

function var_select($name, $def)
{
    txt_select($name, array_keys($_SESSION['vars']), $def);
}

function pair_input_select($name, $value)
{
    echo '<input type="text" name="'.$name.'_txt" value="';
    if (!is_var($value)) echo html_quotes($value);
    echo '"><br/>';
    var_select($name.'_sel', $value);
}

function tri_input_select($name, $value)
{
    echo '<input type="text" name="'.$name.'_txt" value="';
    $sn = service_names();
    if (!in_array($value,$sn) && !is_var($value)) echo html_quotes($value);
    echo '"><br/>';
    var_select($name.'_var', $value);
    txt_select($name.'_srv', $sn, $value);
}

function addedit_rule_value($action, $id, $value)
{
    html_header();
    echo '<form>';
    echo '<input type="hidden" name="a" value="'.$action.'">';
    echo '<input type="hidden" name="i" value="'.$id.'">';
    echo '<table border="1" bgcolor="#eeeeee">';

    echo '<tr><th colspan="4">Comment</th></tr>';

    echo '<tr><td colspan="4">';
    echo '<input type="text" name="comment" value="'.$value['comment'].'" size="75">';
    echo '</td></tr>';
    
    echo '<tr><th>Chain</th><th>Interface</th><th>Protocol</th><th>Protocol subtype</th></tr>';
    
    echo '<tr><td>';
    txt_select('chain', array("INPUT","OUTPUT","FORWARD"), $value['chain']);
    echo '</td>';
    
    echo '<td>';
    pair_input_select('if', $value['if']);
    echo '</td>';

    echo '<td>';
    txt_select('proto', array('','tcp','udp','icmp'), $value['proto']);
    echo '</td>';

    echo '<td>';
    echo '<input type="text" name="subproto" value="'.$value['subproto'].'" size="5">';
    echo '</td>';

    echo '<tr><th>Source</th><th>Source port</th>';
    echo '<th>Destination</th><th>Destination port</th></tr>';

    echo '<td>';
    pair_input_select('src', $value['src']);
    echo '</td>';
    
    echo '<td>';
    tri_input_select('srcport', $value['srcport']);
    echo '</td>';
    
    echo '<td>';
    pair_input_select('dst', $value['dst']);
    echo '</td>';
    
    echo '<td>';
    tri_input_select('dstport', $value['dstport']);
    echo '</td>';

    echo '<tr><th>SYN</th><th>Log?</th><th>Result</th></tr>';
    
    echo '<td>';
    txt_select('syn', array('I','Y','N'), $value['syn']);
    echo '</td>';

    echo '<td>';
    txt_select('log', array('I','Y','N'), $value['log']);
    echo '</td>';

    echo '<td>';
    txt_select('result', array('ACCEPT','DROP','REJECT','LOG'), $value['result']);
    echo '</td>';

    echo '<tr><td colspan="11" align="right">';
    echo '<input type="submit" name="submit" value="Записать"><input type="submit" name="cancel" value="Отменить">';
    echo '</td></tr>';
    
    echo '</table>';
    echo '</form>';
    html_footer();
}

function parse_fields($first, $second, $third)
{
    if ($first)
	return $first;
    if ($second)
	return $second;
    if ($third)
	return $third;
}

function parse_rule_submit()
{
    $rule = array();
    $rule['chain'] = parse_fields($_GET['chain'], '', '');
    $rule['if'] = parse_fields($_GET['if_txt'],$_GET['if_sel'],'');
    $rule['proto'] = parse_fields($_GET['proto'],'','');
    $rule['subproto'] = parse_fields($_GET['subproto'],'','');
    $rule['src'] = parse_fields($_GET['src_txt'],$_GET['src_sel'],'');
    $rule['srcport'] = parse_fields($_GET['srcport_txt'],$_GET['srcport_var'],$_GET['srcport_srv']);
    $rule['dst'] = parse_fields($_GET['dst_txt'],$_GET['dst_sel'],'');
    $rule['dstport'] = parse_fields($_GET['dstport_txt'],$_GET['dstport_var'],$_GET['dstport_srv']);
    $rule['syn'] = parse_fields($_GET['syn'],'','');
    $rule['log'] = parse_fields($_GET['log'],'','');
    $rule['result'] = parse_fields($_GET['result'],'','');
    $rule['comment'] = parse_fields($_GET['comment'],'','');
    return $rule;
}

function edit_rule($rule)
{
    addedit_rule_value("edit", $rule, $_SESSION['rules'][$rule]);
}

function add_rule()
{
    addedit_rule_value("add", 0, array(
		    'chain'=>'INPUT',
		    'if'=>'',
		    'proto'=>'',
		    'subproto'=>'',
		    'src'=>'',
		    'srcport'=>'',
		    'dst'=>'',
		    'dstport'=>'',
		    'syn'=>'I',
		    'log'=>'I',
		    'result'=>'ACCEPT',
		    'comment'=>''
    ));
}

function edit_var($varname)
{
    $value = $_SESSION['vars'][$varname];
    
    html_header();
    echo '<form><input type="hidden" name="a" value="editvar">';
    echo $varname.'<br><input type="hidden" name="var" value="'.html_quotes($varname).'"><input type="text" name="val" size="30" value="'.html_quotes($value).'"><br><input type="submit" name="submit" value="Записать"><input type="submit" name="cancel" value="Отменить">';
    echo '</form>';
    html_footer();
}

function add_var()
{
    html_header();
    echo '<form><input type="hidden" name="a" value="addvar">';
    echo 'Add var<br/>Name: <input type="text" name="var" size="30"><br/>Value: <input type="text" name="val" size="30"><br><input type="submit" name="submit" value="Записать"><input type="submit" name="cancel" value="Отменить"></form>';
    html_footer();
}

function swap_rules($from, $to)
{
    $last = count($_SESSION['rules'])-1;
    
    if ($from < 0 || $from > $last || $to < 0 || $to > $last)
	return;

    $delta = $to - $from;
    if ($delta < 0) { $from = $to; $delta = -$delta; }
	
    $eject = array_splice($_SESSION['rules'], $from, $delta+1);
    $eject = array_reverse($eject);
    array_splice($_SESSION['rules'], $from, 0, $eject);
}

/* --- Start ==================================================== */
switch ($_GET['a']) {
    case 'reset': // reset vars & rules
	$_SESSION['vars'] = array();
	$_SESSION['rules'] = array();
	$_SESSION['services'] = array();
	init_defaults();
	load_config();
	load_services();
	go_home();

    case 'edit': // edit rule
	if ($_GET['cancel']) go_home();
	if ($_GET['submit']) {
	    $_SESSION['rules'][ $_GET['i'] ] = parse_rule_submit();
	    go_home();
	}
	edit_rule($_GET['i']);
	break;
    
    case 'add': // add rule
	if ($_GET['cancel']) go_home();
	if ($_GET['submit']) {
	    $_SESSION['rules'][] = parse_rule_submit();
	    go_home();
	}
	add_rule();
	break;
	
    case 'drop': // delete rule
	unset($_SESSION['rules'][ $_GET['i'] ]);
	go_home();

    case 'ruleup':
	swap_rules($_GET['i']+0, $_GET['i']-1);
	go_home();
	
    case 'ruledown':
	swap_rules($_GET['i']+0, $_GET['i']+1);
	go_home();

    case 'editvar': // edit var
	if ($_GET['cancel']) go_home();
	if ($_GET['submit']) {
	    $_SESSION['vars'][ $_GET['var'] ] = $_GET['val'];
	    go_home();
	}
	edit_var($_GET['i']);
	break;
	
    case 'addvar': // add var
	if ($_GET['error'] == 1) {
	    html_header();
	    echo 'Variable exists! Use "Edit" to change it.<br/>';
	    echo 'Press <a href="'.$_SERVER['PHP_SELF'].'?a=editvar&i='.urlencode($_GET['i']).'">here</a> to edit it now.';
	    echo 'Press <a href="'.$_SERVER['PHP_SELF'].'">here</a> to go back.';
	    html_footer();
	    exit;
	}
	if ($_GET['cancel']) go_home();
	if ($_GET['submit']) {
	    if (@$_SESSION['vars'][ $_GET['var'] ])
		redirect($_SERVER['PHP_SELF'].'?a=addvar&i='.urlencode($_GET['var']).'&error=1');
	    $_SESSION['vars'][ $_GET['var'] ] = $_GET['val'];
	    go_home();
	}
	add_var();
	break;

    case 'dropvar': // delete variable
	unset($_SESSION['vars'][ $_GET['i'] ]);
	go_home();

    case 'dump': // make rc.firewall dump
	dump_config();
	echo 'Config dumped to rc.firewall in your home web directory.<br/>';
        echo 'Press <a href="'.$_SERVER['PHP_SELF'].'">here</a> to go back.';
	exit;
	
    case 'save': // save frw.conf
	save_config();
	echo 'Config saved to "'.CONFIGFILE.'".<br/>';
        echo 'Press <a href="'.$_SERVER['PHP_SELF'].'">here</a> to go back.';
	break;
	
    default:
	if (!$_SESSION['services']) {
	    load_services();
	}

	if (!$_SESSION['vars'])	{
    	    init_defaults();
	    load_config();
	}

	html_header();
	list_rules();
	list_vars();
	html_footer();
	break;
}

?>