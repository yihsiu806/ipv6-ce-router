#
# Copyright (C) 2013, 2014
# Chunghwa Telecommunication Labratories (CHT-TL)
# All rights reserved.
# 
# Redistribution and use of this software in source and binary
# forms, with or without modification, are permitted provided that
# the following conditions and disclaimer are agreed and accepted
# by the user:
# 
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with
#    the distribution.
# 
# 3. Neither the names of the copyrighters, the name of the project
#    which is related to this software (hereinafter referred to as
#    "project") nor the names of the contributors may be used to
#    endorse or promote products derived from this software without
#    specific prior written permission.
# 
# 4. No merchantable use may be permitted without prior written
#    notification to the copyrighters.
# 
# 5. The copyrighters, the project and the contributors may prohibit
#    the use of this software at any time.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHTERS, THE PROJECT AND
# CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING
# BUT NOT LIMITED THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE, ARE DISCLAIMED.  IN NO EVENT SHALL THE
# COPYRIGHTERS, THE PROJECT OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
# $CHT-TL: SAA.pm,v 1.1 2014/05/19 weifen Exp $
#
# 

######################################################################
package SAA;

use Exporter;
@ISA = qw(Exporter);
@EXPORT = qw(
	seqOK 
	seqNG 
	seqERROR 
	seqExitFATAL 
	seqExitNS 
	seqExitWARN 
	seqWarnCheck 
	seqTermination 
	seqSendWait 
	seqCheckNUTAddrConfigured 
	seqCheckNUTAddrConfiguredUcast
	seqCheckNUTAddrConfiguredDAD
	seqCheckNUTAddrConfiguredGA
	seqCheckNUTAddrConfiguredGADAD
	seqPrepareLLA 
  seqPingFromNUT
);

use V6evalTool;
use Carp;
require './config.pl';

use lib '../.';
use DHCPv6_common;
use CPE6_config;

BEGIN { }
END { }

#----- constant values
# nothing

#----- test condition
$debug = 0;			# debug level

$test_interval = "15";          # interval time between tests

$howto_addrconf = "reboot";     # How to configure address of CE-Router?
                                # alternatives are
                                # reboot/boot/ra/manual/manual_async

$wait_addrconf = $wait_addrconf_base + $RetransTimerSec * ($DupAddrDetectTransmits - 1); 
				# time to wait for CE-Router to acturally configure
				# LLA after it sends first DAD NS
				#
				# *test scripts wait for $wait_addrconf [sec]
				#  from the first received DAD NS

$wait_addrconf_with_RA = $wait_addrconf_base + $RetransTimerSec * ($DupAddrDetectTransmits - 1); 
				# time to wait for CE-Router to acturally configure
				# GA or SLA after it sends first DAD NS
				#
				# *test scripts wait for $wait_addrconf_with_RA
				#  [sec] from the first received DAD NS

$ping_dst_addr ="3ffe:501:ffff:aaaa::abcd";
				# address to sent PING from CE-Router


#==============================================
# check if CE-Router's address is configured
#==============================================
sub seqCheckNUTAddrConfiguredDAD($) {
    my ($IF) = @_;
    my (%retsw1, $dad_ns, $dad_na);

    vLog("Check if CE-Router's address is configured");
    %retsw1 = seqSendWait($IF,
			"DAD NS from TN to CE-Router:", DADNS_from_TN_SameDstSameTgt,
			"DAD NA from CE-Router:", $wait_dadna,0, 
			DADNA_from_NUT, DADNA_from_NUT_woTLL);

    if ($retsw1{status}==0) {
			vLog("CE-Router assigned the address to the interface.");
			if ($retsw1{recvFrame} ne DADNA_from_NUT) {
	    	vLogHTML("<FONT COLOR=\"#FF0000\">TN received irregular DAD NA.</FONT>");
	    	$iregdadna = 1;
			}
			return TRUE;
    } elsif($retsw1{status}==1) { #timeout
			vLog("CE-Router's address is not configured.");
			return FALSE;
    } else {
			seqERROR("seqCheckNUTAddrConfiguredDAD: Cannot reach here!"); #exit
    }

}
	
#==============================================
# check if CE-Router's address is configured
#==============================================
sub seqCheckNUTAddrConfigured($) {
    my ($IF) = @_;
    my (%retsw1, $dad_ns, $dad_na);

    vLog("Check if CE-Router's address is configured");
    %retsw1 = seqSendWait($IF,
		"NS from TN to CE-Router:", SOLNS_from_TN_SameTgt,
		"NA from CE-Router:", $wait_solna,0, NA_from_NUT, NA_from_NUT_woTLL);
    if ($retsw1{status}==0) {
	vLog("CE-Router assigned the address to the interface.");
	if ($retsw1{recvFrame} ne NA_from_NUT) {
	    vLogHTML("<FONT COLOR=\"#FF0000\">TN received irregular DAD NA.</FONT>");
	    $iregdadna = 1;
	}
	return TRUE;
    }
    elsif($retsw1{status}==1) { #timeout
	vLog("CE-Router's address is not configured.");
	return FALSE;
    }
    else {
	seqERROR("seqCheckNUTAddrConfigured: Cannot reach here!"); #exit
    }

}

#==============================================
# check if CE-Router's address is configured
#==============================================
sub seqCheckNUTAddrConfiguredUcast($) {
    my ($IF) = @_;
    my (%retsw1, $dad_ns, $dad_na);

    vLog("Check if CE-Router's address is configured");
    %retsw1 = seqSendWait($IF,
			"NS from TN to CE-Router:", NS_from_TN_SrcDstUni,
			"NA from CE-Router:", $wait_solna,0, NA_from_NUT, NA_from_NUT_woTLL);
    if ($retsw1{status}==0) {
			vLog("CE-Router assigned the address to the interface.");
			return TRUE;
    } elsif($retsw1{status}==1) { #timeout
			vLog("CE-Router's address is not configured.");
			return FALSE;
    } else {
			seqERROR("seqCheckNUTAddrConfiguredUcast: Cannot reach here!"); #exit
    }

}

#==============================================
# check if CE-Router's address is configured
#==============================================
sub seqCheckNUTAddrConfiguredGADAD($$@) {
    my ($IF,$Frame_Send,@Frame_Recv) = @_;
    my (%retsw1, $dad_ns, $dad_na);

    vLog("Check if CE-Router's address is configured");
    %retsw1 = seqSendWait($IF,
	"DAD NS from TN to CE-Router:", $Frame_Send,
	"DAD NA from CE-Router:", $wait_dadna,0, @Frame_Recv);
    if ($retsw1{status}==0) {
	vLog("CE-Router assigned the address to the interface.");
	return TRUE;
    }
    elsif($retsw1{status}==1) { #timeout
	vLog("CE-Router's address is not configured.");
	return FALSE;
    }
    else {
	seqERROR("seqCheckNUTAddrConfiguredGA: Cannot reach here!"); #exit
    }

}

#==============================================
# check if CE-Router's address is configured
#==============================================
sub seqCheckNUTAddrConfiguredGA($$@) {
    my ($IF,$Frame_Send,@Frame_Recv) = @_;
    my (%retsw1);

    vLog("Check if CE-Router's address is configured");
    %retsw1 = seqSendWait($IF,
	"NS from TN to CE-Router:", $Frame_Send,
	"NA from CE-Router:", $wait_solna,0, @Frame_Recv);
    if ($retsw1{status}==0) {
	vLog("CE-Router assigned the address to the interface.");
	return TRUE;
    }
    elsif($retsw1{status}==1) { #timeout
	vLog("CE-Router's address is not configured.");
	return FALSE;
    }
    else {
	seqERROR("seqCheckNUTAddrConfiguredGA: Cannot reach here!"); #exit
    }

}

#==============================================
# send a frame and wait frames
#==============================================
sub seqSendWait ($$$$$$@) {
    my ($IF,
	$msg_send,     # string, send frame description sample: "DAD NS from TN to CE-Router:"
	$frame_send,   # send framename in packet.def file
	$msg_wait,     # string, wait frame description sample: "DAD NS from CE-Router:"
	$timeout,      # int [sec], wait timeout for vRecv()
	$count,        # int, wait packet cout for vRecv()
	@frame_wait    # wait framenames in packet.def file
	) = @_;
    my (%ret, $frames_wait);

    vLog("Send $msg_send $frame_send");
    vClear($IF);
    %ret=vSend($IF, $frame_send);
    seqERROR(vErrmsg(%ret)) if $ret{status} != 0 ;

    $frames_wait = join(',',@frame_wait);
    vLog("Wait $msg_wait $frames_wait");
#   %ret=vRecv($IF,$timeout,$ret{sentTime1},$count, @frame_wait);
    %ret=vRecv($IF,$timeout,0,$count, @frame_wait);
    vLog("Received packet count=$ret{recvCount}");
    if($ret{status}==0) {
	vLog("Received $msg_wait $ret{recvFrame}");
    }elsif($ret{status}==1) {
	vLog("Wait $msg_wait timeout");
    }
    return %ret;
    
}


#==============================================
# send a ICMP echo request from CE-Router
#==============================================
sub seqPingFromNUT ($$$@) {
    my ($IF,
	$timeout,      # int [sec], wait timeout for vRecv()
	$count,        # int, wait packet cout for vRecv()
	@frame_wait    # wait framenames in packet.def file
	) = @_;
    my ($rret, $frames_wait, %ret);

    vLog("Send Ping From CE-Router to $ping_dst_addr");
    vClear($IF);
    $rret=vRemote("ping6.rmt","","timeout=$timeout","addr=$ping_dst_addr");
    vLog("ping_to_offlink.rmt returned status $rret");

    seqERROR(vErrmsg(%ret)) if $rret != 0 ;

    $frames_wait = join(',',@frame_wait);
    vLog("Wait $msg_wait $frames_wait");


    %ret=vRecv($IF,$timeout,0,$count, @frame_wait,SOLNS_from_NUT_to_TN,SOLNS_from_NUT_to_TN_srcGlobal,SOLNS_from_NUT_to_TN_DstMulti,SOLNS_from_NUT_to_TN_srcGlobal_DstMulti);

    if( $ret{status} != 0) {
        vLogHTML("CE-Router can not send Echo Request<BR>");
    }elsif( $ret{recvFrame} eq 'SOLNS_from_NUT_to_TN' ||
     $ret{recvFrame} eq 'SOLNS_from_NUT_to_TN_srcGlobal' ||  
     $ret{recvFrame} eq 'SOLNS_from_NUT_to_TN_DstMulti' ||  
     $ret{recvFrame} eq 'SOLNS_from_NUT_to_TN_srcGlobal_DstMulti') {
        if( $ret{recvFrame} eq 'SOLNS_from_NUT_to_TN' || 
            $ret{recvFrame} eq 'SOLNS_from_NUT_to_TN_DstMulti' ) {
            vSend($IF, NA_from_TN_to_NUT);
        }elsif( $ret{recvFrame} eq 'SOLNS_from_NUT_to_TN_srcGlobal' || 
                $ret{recvFrame} eq 'SOLNS_from_NUT_to_TN_srcGlobal_DstMulti') {
            vSend($IF, NA_from_TN_to_NUT_dstGlobal);
        }

        %ret=vRecv($IF, 5,0,0, @frame_wait);
        if( $ret{status} != 0) {
            vLogHTML("TN COULD NOT receive Echo Request from CE-Router<BR>");
            vLogHTML('<FONT COLOR="#FF0000">NG</FONT>');
            vClear($IF);
            exit $V6evalTool::exitFail;
        }else {
# Correct Case
            vLogHTML("TN received Echo Request from CE-Router<BR>");
            vLogHTML('OK');
        }
    }else {
    # Correct Case
        vLogHTML("TN received Echo Request from CE-Router<BR>");
        vLogHTML('OK');
    }

    return $ret{status};
    
}


#=================================================
# Test Termination
#=================================================
sub seqTermination() {
    &$main::term_handler if defined $main::term_handler;
}

#=================================================
# Fail Check before exit OK
#=================================================
sub seqWarnCheck() {
    my($wc);
    $wc = 0;
    if ($initfail == 1) {
	vLog("Note: There is a failure in initialization phase.");
	$initfail=0; $wc++;
    } elsif ($initfail > 1) {
	vLog("Note: There are $initfail failures in initialization phase.");
	$initfail=0;  $wc++;
    }
    if ($iregdadns > 0) {
	vLog("Note: There is an irregular DAD NS.");
	$iregdadns=0; $wc++;
    }	
    if ($iregdadna > 0) {
	vLog("Note: There is an irregular DAD NA.");
	$iregdadna=0; $wc++;
    }	

    if ($wc > 0) {
	return WARN;
    }else{
	return OK;
    }

}

#=================================================
# sequence exit OK
#=================================================
sub seqOK() {
    seqExitWARN() if seqWarnCheck() eq 'WARN';
    vLog(OK);
    seqTermination();
    vLog("*** EOT ***");
    exit $V6evalTool::exitPass;
}

#=================================================
# sequence exit NG
#=================================================
sub seqNG() {
    seqWarnCheck();
    vLog(NG);
    seqTermination();
    vLog("*** EOT ***");
    exit $V6evalTool::exitFail;
}

#=================================================
# sequence exit ERROR with error message
#=================================================
sub seqERROR($) {
    my ($msg) = @_;
    vLog($msg);
    vLog(ERROR);
    seqTermination();
    vLog("*** EOT ***");
    confess "Sequence Stop" if $debug > 0;
    exit $V6evalTool::exitFail;

}

sub seqExitFATAL() {
    vLog("FATAL ERROR, CE-Router fall into strange state.");
    seqTermination();
    vLog("*** EOT ***");
    exit $V6evalTool::exitFail;
}

sub seqExitNS() {
    vLog("Not yet supported");
    seqTermination();
    vLog("*** EOT ***");
    exit $V6evalTool::exitNS;
}

sub seqExitWARN() {
    seqWarnCheck();
    vLog(WARN);
    seqTermination();
    vLog("*** EOT ***");
    exit $V6evalTool::exitWarn;
}

#==============================================
# send a frame and wait frames
#==============================================
sub seqPrepareLLA ($$) {

    my ($IF, $system) = @_;
    my (%ret, $nutlla);

    if ( $system ne "manual" or $SAA::lla_autoconf eq "YES") {
        return 0;
    }

    vClear($IF);

    vLog("Send PreparationPkt");
    %ret=vSend($IF, PreparationPkt);
    seqERROR(vErrmsg(%ret)) if $ret{status} != 0 ;

    vLog("Wait PreparationPkt");
#    %ret=vRecv($IF,1,$ret{sentTime1},1, PreparationPkt);
    %ret=vRecv($IF,1,0,1, PreparationPkt);
    vLog("Received packet count=$ret{recvCount}");
    if($ret{status}==0) {
	vLog("Received $ret{recvFrame}");
    }elsif($ret{status}==1) {
	vLog("Wait 5 [sec] timeout");
    }

    $nutlla=$ret{'Frame_Ether.Packet_IPv6.Hdr_IPv6.SourceAddress'};
    vLog("");
    vLog("===================================================");
    vLog("If CE-Router can save link-local address configuration");
    vLog("  1. set link-local address $nutlla on $V6evalTool::NutDef{'Link0_device'} and save.");
    vLog("  2. press ENTER key here");
    vLog("  3. reboot CE-Router");
    vLog("  *If CE-Router transmits some packets when rebooting, swap 2 and 3.");
    vLog("");
    vLog("If CE-Router can NOT save link-local address configuration");
    vLog("  1. reboot CE-Router");
    vLog("  2. wait for CE-Router to boot completely");
    vLog("  3. press ENTER key here");
    vLog("  4. set link-local address $nutlla on $V6evalTool::NutDef{'Link0_device'}.");
    vLog("===================================================");
    vLog("");


    return 0;
    
}



#======================================================================#
# sequence to verify that IP operation was disabled                    #
#======================================================================#
# sub
# seqVrfyIpOperation($$)
# {
# 	my ($Link0, $Link1) = @_;
# 
# 	my %ret = ();
# 
# 	my $MAX_MULTICAST_SOLICIT = 3;
# 
# 	if($V6evalTool::NutDef{'Type'} eq 'router') {
# 		# 11. If the CE-Router is a Router, enable interface on Link A.
# 		#     TN2 transmits an Echo Request to TN2's Global Address
# 		#     with a first hop through the CE-Router.
# 
# 		vCapture($Link1);
# 
# 		vClear($Link0);
# 		vClear($Link1);
# 
# 		vSend($Link0, 'off_ereq_link0');
# 
# 		# 12. If the CE-Router is a router,
# 		#     observe packet captures on Link A and Link B.
# 
# 		%ret=vRecv($Link1,
# 			$RetransTimerSec * $MAX_MULTICAST_SOLICIT, 0, 0, 'mcast_ns_link1');
# 
# 		unless($ret{'status'}){
# 			# Step 12: If the CE-Router is a Router,
# 			#          the CE-Router must NOT forward the Echo Request
# 			#          to TN2 on Link A.
# 
# 			vLog("CE-Router had transmitted solicited NS to forward the packet.");
# 
# 			seqNG();
# 		}
# 
# 		vStop($Link1);
# 	} else {
# 		# 11. If the CE-Router is a host,
# 		#     TR1 transmits a Router Advertisement with a prefix option.
# 
# 		vClear($Link0);
# 
# 		vSend($Link0, 'RA_GA0_VLT40');
# 
# 		# 12. If the CE-Router is a host,
# 		#     observe packet captures on Link B.
# 
# 		%ret=vRecv($Link0, $wait_dadns{'ra'}, 0, 0, 'DADNS_from_NUT_GA0Tgt');
# 
# 		unless($ret{'status'}){
# 			# Step 12: If the CE-Router is a host,
# 			#          the CE-Router must NOT transmit a DAD NS
# 			#          for its global address.
# 
# 			vLog("CE-Router had transmitted DAD NS for its Global address.");
# 			seqNG();
# 		}
# 
# 		vLog("CE-Router had not transmitted DAD NS for Global address.");
# 	}
# 
# 	return(seqOK());
# }

1;
###end
######################################################################
__END__
