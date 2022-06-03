#!/bin/bash

# Thus script is to add iptables rules for logging closed port probes on a clearos system.
# This should be called from /etc/clearos/firewall.d/90-attack-detector (end of file before "exit")

#set correct interfce per machine
interface=("ppp+")

# Add iptables rule function
addRules()
{
	if [[ -z $1 ]] ;then
		if [[ -z $ports ]] ; then
			port_param=''
			# if only 1 port the rule uses different paramaters
			elif [[ "$ports" == *","* ]] ; then
				port_param='-m multiport ! --dports'
 		 	else
  				port_param='! --dport'
 		fi
		for iface in "${interface[@]}" ; do
			iptables -A INPUT -i $iface -m state --state NEW -p $proto $port_param $ports -j \
LOG --log-prefix "Closed port probe: " --log-level 4 -m comment --comment \
"RULE # $((rulenum++)) of $total_rules port probing LOG excluding -> $ports"
		done
	fi
}

# Get the open ports from fw config
# TCP ports
mapfile -t tcp_list < <(grep "0x1" /etc/clearos/firewall.conf | grep '|6|' | awk -F"|" '{print $6}' | sort -u)
# UDP ports
mapfile -t udp_list < <(grep "0x1" /etc/clearos/firewall.conf | grep '|17|' | awk -F"|" '{print $6}' | sort -u)

# If test mode export port list and exit
if [[ $1 == "test_ip" ]] ; then
	echo "${tcp_list[@]}" > /tmp/tcp_port_list
	echo "${udl_list[@]}" > /tmp/udp_port_list
	exit 0
#fi

#if ! [[ $1 == "test_ip" ]] ; then
else
	# Set some vars for the iptables rule comments
	rulenum=1 # Rule # for the iptables comment
	tcp_rules=$(awk -v v1=${#tcp_list[@]} 'BEGIN {print int(0.99999 + v1/15)}')
	udp_rules=$(awk -v v1=${#udp_list[@]} 'BEGIN {print int(0.99999 + v1/15)}')
	total_rules=$((tcp_rules+udp_rules))

	# TCP Rules
	proto='tcp'
	if [[ -z ${tcp_list[@]} ]] ; then 
		ports=''
		addRules
	else
		for (( x = 0; x < ${#tcp_list[@]}; x += 15 )); do
		# iptables allows max 15 ports per rule so split it
			ports=$(echo ${tcp_list[*]:x:15} | tr ' ' ',' | sed 's/,$//')
			addRules
		done
	fi
	
	# UDP Rules
	proto='udp'
	if [[ -z ${udp_list[@]} ]] ; then 
		ports=''
		addRules
	else
		for (( x = 0; x < ${#udp_list[@]}; x += 15 )); do
			ports=$(echo ${udp_list[*]:x:15} | tr ' ' ',' | sed 's/,$//')
			addRules
		done
	fi
fi
