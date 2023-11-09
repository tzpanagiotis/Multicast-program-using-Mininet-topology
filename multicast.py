#Name: Panagiotis Tzannis AEM: 2698

# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Two OpenFlow 1.0 L3 Static Routers and two OpenFlow 1.0 L2 learning switches.
"""

from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import igmp
from ryu.lib.packet import ether_types
import ipaddress
import pandas as pd

test_list = [([2, 1, "239.0.0.1"]), ([2, 1, "239.0.0.2"]), ([3, 1, "239.0.0.1"]), ([3, 1, "239.0.0.2"]) ]

class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    def add_flow(self, datapath, match, actions):
        ofproto = datapath.ofproto

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def router_features_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id

        if dpid == 0x1A:

           #Forwarding of the high-priority traffic(ToS = 8)

           actions = [datapath.ofproto_parser.OFPActionSetDlSrc("00:00:00:00:05:01"), datapath.ofproto_parser.OFPActionSetDlDst("00:00:00:00:05:02"),
           datapath.ofproto_parser.OFPActionOutput(4)]
           match = datapath.ofproto_parser.OFPMatch(nw_dst = "192.168.2.0", nw_dst_mask = 24, dl_type = ether_types.ETH_TYPE_IP, nw_tos=8)

           self.add_flow(datapath, match, actions)

           #Forwarding of multicast groups
           
           actions = [datapath.ofproto_parser.OFPActionSetDlSrc("00:00:00:00:01:01"), datapath.ofproto_parser.OFPActionSetDlDst("00:00:00:00:01:02"),
           datapath.ofproto_parser.OFPActionOutput(2)]
           match = datapath.ofproto_parser.OFPMatch(nw_dst = "239.0.0.1", dl_type = ether_types.ETH_TYPE_IP, in_port = 1)

           self.add_flow(datapath, match, actions)

           actions = [datapath.ofproto_parser.OFPActionSetDlSrc("00:00:00:00:01:01"), datapath.ofproto_parser.OFPActionSetDlDst("00:00:00:00:01:03"),
           datapath.ofproto_parser.OFPActionOutput(2)]
           match = datapath.ofproto_parser.OFPMatch(nw_dst = "239.0.0.2", dl_type = ether_types.ETH_TYPE_IP, in_port = 1)

           self.add_flow(datapath, match, actions)

           actions = [datapath.ofproto_parser.OFPActionSetDlSrc("00:00:00:00:03:01"), datapath.ofproto_parser.OFPActionSetDlDst("00:00:00:00:03:02"),
           datapath.ofproto_parser.OFPActionOutput(1)]
           match = datapath.ofproto_parser.OFPMatch(nw_dst = "239.0.0.0", nw_dst_mask = 24, dl_type = ether_types.ETH_TYPE_IP, in_port = 2)

           self.add_flow(datapath, match, actions)

        if dpid == 0x1B:

           #Forwarding of the high-priority traffic(ToS = 8)

           actions = [datapath.ofproto_parser.OFPActionSetDlSrc("00:00:00:00:05:02"), datapath.ofproto_parser.OFPActionSetDlDst("00:00:00:00:05:01"),
           datapath.ofproto_parser.OFPActionOutput(4)]
           match = datapath.ofproto_parser.OFPMatch(nw_dst = "192.168.1.0", nw_dst_mask = 24, dl_type = ether_types.ETH_TYPE_IP, nw_tos=8)

           self.add_flow(datapath, match, actions)

           #Forwarding of multicast groups

           actions = [datapath.ofproto_parser.OFPActionSetDlSrc("00:00:00:00:02:01"), datapath.ofproto_parser.OFPActionSetDlDst("00:00:00:00:02:02"),
           datapath.ofproto_parser.OFPActionOutput(2)]
           match = datapath.ofproto_parser.OFPMatch(nw_dst = "239.0.0.1", dl_type = ether_types.ETH_TYPE_IP, in_port = 1)

           self.add_flow(datapath, match, actions)

           actions = [datapath.ofproto_parser.OFPActionSetDlSrc("00:00:00:00:02:01"), datapath.ofproto_parser.OFPActionSetDlDst("00:00:00:00:02:03"),
           datapath.ofproto_parser.OFPActionOutput(2)]
           match = datapath.ofproto_parser.OFPMatch(nw_dst = "239.0.0.2", dl_type = ether_types.ETH_TYPE_IP, in_port = 1)

           self.add_flow(datapath, match, actions)

           actions = [datapath.ofproto_parser.OFPActionSetDlSrc("00:00:00:00:03:02"), datapath.ofproto_parser.OFPActionSetDlDst("00:00:00:00:03:01"),
           datapath.ofproto_parser.OFPActionOutput(1)]
           match = datapath.ofproto_parser.OFPMatch(nw_dst = "239.0.0.0", nw_dst_mask = 24, dl_type = ether_types.ETH_TYPE_IP, in_port = 2)

           self.add_flow(datapath, match, actions)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):

        global test_list

        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        in_port = msg.in_port

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        igmp_pkt = pkt.get_protocol(igmp.igmp)

        dst = eth.dst
        src = eth.src
        ethertype = eth.ethertype

        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s in_port=%s", hex(dpid).ljust(4), hex(ethertype), src, dst, msg.in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = msg.in_port

        if dpid == 0x1A:
            if ethertype == ether_types.ETH_TYPE_ARP: # this packet is ARP packet
                if(arp_pkt.opcode == arp.ARP_REQUEST):
                   if(arp_pkt.dst_ip == '192.168.1.1'):
                      dst_ip = arp_pkt.dst_ip
                      src_ip = arp_pkt.src_ip
                      dst = '00:00:00:00:01:01'
                      pkt = packet.Packet()
                      pkt.add_protocol(ethernet.ethernet(ethertype=0x806,dst=src,src=dst))
                      pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY, src_mac=dst, src_ip=dst_ip, dst_mac=src, dst_ip=src_ip))
                      self.send_packet(datapath,in_port,pkt)
                   if(arp_pkt.dst_ip == '192.168.2.1'):
                      dst_ip = arp_pkt.dst_ip
                      src_ip = arp_pkt.src_ip
                      dst = '00:00:00:00:03:02'
                      pkt = packet.Packet()
                      pkt.add_protocol(ethernet.ethernet(ethertype=0x806,dst=src,src=dst))
                      pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY, src_mac=dst, src_ip=dst_ip, dst_mac=src, dst_ip=src_ip))
                      self.send_packet(datapath,in_port,pkt)
                return
            elif ethertype == ether_types.ETH_TYPE_IP: # this packet is IP packet

                ip_net1 = ipaddress.ip_network("192.168.1.0/24")
                ip_net2 = ipaddress.ip_network("192.168.2.0/24")
                ip_dst = ipaddress.ip_address(ip_pkt.dst)

                data = None
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                   data = msg.data

                if(ip_dst in ip_net1):
                   if(ip_pkt.dst == "192.168.1.2"):
                      actions = [datapath.ofproto_parser.OFPActionSetDlSrc("00:00:00:00:01:01"), datapath.ofproto_parser.OFPActionSetDlDst("00:00:00:00:01:02"),
                      datapath.ofproto_parser.OFPActionOutput(2)]
                      match = datapath.ofproto_parser.OFPMatch(nw_dst = "192.168.1.2", dl_type = ether_types.ETH_TYPE_IP)

                      self.add_flow(datapath, match, actions)
                      out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port, actions=actions, data=data)
                      datapath.send_msg(out)

                   if(ip_pkt.dst == "192.168.1.3"):
                      actions = [datapath.ofproto_parser.OFPActionSetDlSrc("00:00:00:00:01:01"), datapath.ofproto_parser.OFPActionSetDlDst("00:00:00:00:01:03"),
                      datapath.ofproto_parser.OFPActionOutput(2)]
                      match = datapath.ofproto_parser.OFPMatch(nw_dst = "192.168.1.3", dl_type = ether_types.ETH_TYPE_IP)

                      self.add_flow(datapath, match, actions)
                      out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port, actions=actions, data=data)
                      datapath.send_msg(out)


                elif(ip_dst in ip_net2):
                   actions = [datapath.ofproto_parser.OFPActionSetDlSrc("00:00:00:00:03:01"), datapath.ofproto_parser.OFPActionSetDlDst("00:00:00:00:03:02"),
                   datapath.ofproto_parser.OFPActionOutput(1)]
                   match = datapath.ofproto_parser.OFPMatch(nw_dst = "192.168.2.0", nw_dst_mask = 24, dl_type = ether_types.ETH_TYPE_IP)

                   self.add_flow(datapath, match, actions)
                   out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port, actions=actions, data=data)
                   datapath.send_msg(out)


                else:
                   pkt = packet.Packet()
                   new_data = msg.data[14:]

                   eth_src = eth.src
                   pkt.add_protocol(ethernet.ethernet(ethertype=0x800,dst=eth_src,src="00:00:00:00:01:01"))
                   pkt.add_protocol(ipv4.ipv4(src="192.168.1.1", dst=ip_pkt.src, proto = 1))
                   icmp_data = icmp.dest_unreach(data_len= len(new_data), data=new_data)
                   pkt.add_protocol(icmp.icmp(type_=3, code= 7, data= icmp_data))

                   self.send_packet(datapath,in_port,pkt)
                   return

                return
            return
        if dpid == 0x1B:
            if ethertype == ether_types.ETH_TYPE_ARP: # this packet is ARP packet
                if(arp_pkt.opcode == arp.ARP_REQUEST):
                   if(arp_pkt.dst_ip == '192.168.1.1'):
                      dst_ip = arp_pkt.dst_ip
                      src_ip = arp_pkt.src_ip
                      dst = '00:00:00:00:03:01'
                      pkt = packet.Packet()
                      pkt.add_protocol(ethernet.ethernet(ethertype=0x806,dst=src,src=dst))
                      pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY, src_mac=dst, src_ip=dst_ip, dst_mac=src, dst_ip=src_ip))
                      self.send_packet(datapath,in_port,pkt)
                   if(arp_pkt.dst_ip == '192.168.2.1'):
                      dst_ip = arp_pkt.dst_ip
                      src_ip = arp_pkt.src_ip
                      dst = '00:00:00:00:02:01'
                      pkt = packet.Packet()
                      pkt.add_protocol(ethernet.ethernet(ethertype=0x806,dst=src,src=dst))
                      pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY, src_mac=dst, src_ip=dst_ip, dst_mac=src, dst_ip=src_ip))
                      self.send_packet(datapath,in_port,pkt)
                return
            elif ethertype == ether_types.ETH_TYPE_IP: # this packet is IP packet

                ip_net1 = ipaddress.ip_network("192.168.1.0/24")
                ip_net2 = ipaddress.ip_network("192.168.2.0/24")
                ip_dst = ipaddress.ip_address(ip_pkt.dst)

                data = None
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                   data = msg.data

                if(ip_dst in ip_net2):
                   if(ip_pkt.dst == "192.168.2.2"):
                      actions = [datapath.ofproto_parser.OFPActionSetDlSrc("00:00:00:00:02:01"), datapath.ofproto_parser.OFPActionSetDlDst("00:00:00:00:02:02"),
                      datapath.ofproto_parser.OFPActionOutput(2)]
                      match = datapath.ofproto_parser.OFPMatch(nw_dst = "192.168.2.2", dl_type = ether_types.ETH_TYPE_IP)

                      self.add_flow(datapath, match, actions)
                      out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port, actions=actions, data=data)
                      datapath.send_msg(out)

                   if(ip_pkt.dst == "192.168.2.3"):
                      actions = [datapath.ofproto_parser.OFPActionSetDlSrc("00:00:00:00:02:01"), datapath.ofproto_parser.OFPActionSetDlDst("00:00:00:00:02:03"),
                      datapath.ofproto_parser.OFPActionOutput(2)]
                      match = datapath.ofproto_parser.OFPMatch(nw_dst = "192.168.2.3", dl_type = ether_types.ETH_TYPE_IP)

                      self.add_flow(datapath, match, actions)
                      out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port, actions=actions, data=data)
                      datapath.send_msg(out)

                elif(ip_dst in ip_net1):
                   actions = [datapath.ofproto_parser.OFPActionSetDlSrc("00:00:00:00:03:02"), datapath.ofproto_parser.OFPActionSetDlDst("00:00:00:00:03:01"),
                   datapath.ofproto_parser.OFPActionOutput(1)]
                   match = datapath.ofproto_parser.OFPMatch(nw_dst = "192.168.1.0", nw_dst_mask = 24, dl_type = ether_types.ETH_TYPE_IP)

                   self.add_flow(datapath, match, actions)
                   out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port, actions=actions, data=data)
                   datapath.send_msg(out)

                else:
                   pkt = packet.Packet()
                   new_data = msg.data[14:]

                   pkt.add_protocol(ethernet.ethernet(ethertype=0x800,dst=src,src="00:00:00:00:02:01"))
                   pkt.add_protocol(ipv4.ipv4(src="192.168.2.1", dst=ip_pkt.src, proto = 1))
                   icmp_data = icmp.dest_unreach(data_len= len(new_data), data=new_data)
                   pkt.add_protocol(icmp.icmp(type_=3, code= 7, data= icmp_data))

                   self.send_packet(datapath,in_port,pkt)
                   return

                return
            return


        if((dpid == 0X2) | (dpid == 0X3)):
           if ethertype == ether_types.ETH_TYPE_IP:
              #If the packet is IGMP, the Dpid, inport and multicast group are stored to a list.
              if(ip_pkt.proto == 2):
                test_list.append([dpid, in_port, igmp_pkt.records[0].address])
              elif((ip_pkt.dst == "239.0.0.1") | (ip_pkt.dst == "239.0.0.2")):

                data = None
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                   data = msg.data

                #Remove duplicates from list
                res = []
                for i in test_list:
                   if i not in res:
                     res.append(i)

                #Get the the inports, based on the Dpid and the multicast group.
                now_port = []
                for item in res:
                   if((item[0] == dpid)&(item[2] == ip_pkt.dst)&(item[1] != msg.in_port)):
                      now_port.append(item[1])

                actions = []
                for i in now_port:
                    actions.append(datapath.ofproto_parser.OFPActionOutput(i))

                match = datapath.ofproto_parser.OFPMatch(nw_dst = ip_pkt.dst, in_port = msg.in_port , dl_type = ether_types.ETH_TYPE_IP)
                self.add_flow(datapath, match, actions)
                out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port, actions=actions, data=data)
                datapath.send_msg(out)

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        match = datapath.ofproto_parser.OFPMatch(
            in_port=msg.in_port, dl_dst=haddr_to_bin(dst))

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            self.add_flow(datapath, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions, data=data)
        datapath.send_msg(out)

    def send_packet(self,datapath,port,pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        data = pkt.data
        action = [parser.OFPActionOutput(port)]
        out = parser.OFPPacketOut(datapath = datapath,buffer_id = ofproto.OFP_NO_BUFFER,in_port = ofproto.OFPP_CONTROLLER,actions = action,data=data)
        datapath.send_msg(out)


    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)
