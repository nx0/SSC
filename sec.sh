#!/bin/bash

GREEN=`tput setaf 2`
RED=`tput setaf 1`
YELLOW=`tput setaf 3`
ENDCOLOR=`tput sgr0`
BGA=`tput setb 7`
BGG=`tput setb 2`
BGN=`tput setb 0`
BGR=`tput setb 4`
BGY=`tput setb 6`

NEG=`tput bold`
UNDER=`tput smul`
NUNDER=`tput rmul`

RULEDIR="`dirname $0`/sec/"
SERROR=0
SOK=0
TOTAL=0

function banner {

echo "	 ___ ___  ___ 
	/ __/ __|/ __| [Simple Security Checker]
	\__ \__ \ (__ 
	|___/___/\___|
	by: Francisco J. Valero - francisco.valero@masvoz.es
"

}


function c {
	CHECK=`cat $1 2>/dev/null`
	MUSTBE=$2
	if [ -f "$1" ]; then
		if [ "$CHECK" != "$MUSTBE" ]; then
			let SERROR=$SERROR+1
			echo "${BGR}Error.${ENDCOLOR}${RED} $1, seteado a $CHECK${ENDCOLOR}"
		else
			let SOK=$SOK+1
			echo "${GREEN}Ok${ENDCOLOR} $1, seteado a $CHECK"	
		fi

		let TOTAL=$TOTAL+1
	else
		echo "${YELLOW}Info.${ENDCOLOR} $1, no existe"
	fi
}

function cc {
	aaa=`cat $1` 
	echo "${YELLOW}Info.${ENDCOLOR} $1, seteado a $aaa"
	#let TOTAL=$TOTAL+1
}

function header {
	echo -e "\n${BGN}---| $1 |---${ENDCOLOR}"
}

function header_check {
	#echo -en "\n${BGN} $1 ... ${ENDCOLOR}"
	echo -en "$1 ... "
}

# check sysctl system hardening tcp ip stack
function sysctl_ {
	header_check "comprobando ${NEG}$1${ENDCOLOR}"
	CHECK=`sysctl $1| awk '{ print $NF }'`
	MUSTBE=$2
	if [ "$CHECK" != "$MUSTBE" ]; then
		EXPLANATION=""
		LONGEXP=""
		#reactfix="sysctl_fix $1 $2"
		return 1
	else
		EXPLANATION=""
		LONGEXP=""
		return 0
	fi
}

function wrap {
	$1 $2 $3
	case $? in
		0)
			echo -n " [${GREEN}OK${ENDCOLOR} | set: ${NEG}$CHECK${ENDCOLOR}] $EXPLANATION"
			if [ "$LONGEXP" != "" ]; then
				echo " (${NEG}${YELLOW}i:${ENDCOLOR} $LONGEXP)"
			else
				echo ""
			fi
			let SOK=$SOK+1
		;;
		1)
			echo "[${BGR}Error${ENDCOLOR} | set: $CHECK/debe ser: ${NEG}$3${ENDCOLOR}] $EXPLANATION"

			# comprobar funcion
			parsefix=`echo $reactfix| awk '{ print $1 }'`
			if [ "$reactfix" != "" ]; then
				echo -n "${YELLOW}info:${ENDCOLOR} fixing with: ${UNDER}$parsefix${NUNDER} "
				reactive $reactfix
			fi
			let SERROR=$SERROR+1
		;;
	esac

	let TOTAL=$TOTAL+1
}

function cmd_iptables_badflags {
	header_check "comprobando badflags"
	CMD=`iptables -L -v -n | grep -i "tcp flags"`
	if [ "$CMD" != "" ]; then
		LONGEXP="no permitir trafico con flags erroneas"
		EXPLANATION="BADFLAGS SET"
		return 0
	else
		EXPLANATION="BADFLAGS NOT SET"
		return 1
	fi
}

function cmd_iptables_burst {
	header_check "comnprobando burst"
	CMD=`iptables -L -v -n | grep -i "tcp flags"`

	if [ "$CMD" != "" ]; then
		LONGEXP="activando las reglas de burst para evitar los ataques DoS"
                EXPLANATION="BURST SET"
                return 0
        else
                EXPLANATION="NO BURST SET"
                return 1
        fi
}

function cmd_iptables_sec {
	header_check "comprobando chain sec"
	CMD=`iptables -L INPUT -n| grep SECURITY`

	if [ "$CMD" != "" ]; then
		LONGEXP="reglas de security activadas en INPUT"
                EXPLANATION="chain set en input"
                return 0
        else
                EXPLANATION="no security in input"
                return 1
        fi

}


function showvalue {
	header_check "comprobando $1"
	sysctl $1 | awk '{ print $NF }'
}



banner
case $1 in

	"-c")
		if [ "$2" == "-r" ]; then
			if [ -f ${RULEDIR}$3.checks ]; then
				checkname="${RULEDIR}$3.checks"
				echo ""
				echo "Cargando fichero de checks \"${NEG}$3${ENDCOLOR}\""
				source ${RULEDIR}/basic.functions
				source ${RULEDIR}$3.functions
				source $checkname
				stats
			else
				echo "no existe el check $3"
				exit 0
			fi
		else
			echo "No se definieron checks, cargando \"${NEG}basicos${ENDCOLOR}\"."
			echo "Para cargar checks usa la opción \"${NEG}-r${ENDCOLOR}\"."
			source ${RULEDIR}/basic.functions
			source ${RULEDIR}/basic.checks
			stats
		fi
	;;
*)
	echo "==== [HELP] ====" 
	echo "[-c] perform the check "
	echo "[-r] reglas a comprobar "
	if [ -d "$RULEDIR" ]; then
		for i in `ls -l ${RULEDIR}| awk '{ print $NF }' | grep checks`; do
			getinfo=`cat ${RULEDIR}$i| grep "info:" | awk -F ":" '{ print $2 }'`
			echo "* $i: $getinfo" 
		done | column -t -s ":"
	fi
	;;
esac
