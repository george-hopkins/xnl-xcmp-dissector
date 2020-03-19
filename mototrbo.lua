local p_moto = Proto("mototrbo", "Mototrbo");

local vs_commands = {
	[0x70] = "XNL/XCMP Packet",
	[0x80] = "Group Voice Call",
	[0x81] = "Private Voice Call",
	[0x83] = "Group Data Call",
	[0x84] = "Private Data Call",
	[0x90] = "Registration Request",
	[0x91] = "Registration Reply",
	[0x92] = "Peer List Request",
	[0x93] = "Peer List Reply",
	[0x94] = "Peer Register Request",
	[0x95] = "Peer Register Reply",
	[0x96] = "Master Keep Alive Request",
	[0x97] = "Master Keep Alive Reply",
	[0x98] = "Peer Keep Alive Request",
	[0x99] = "Peer Keep Alive Reply",
	[0x9A] = "Deregistration Request"
}

local vs_linktype = {
	[4] = "IP Site Connect",
	[8] = "Capacity Plus"
}

local f_command = ProtoField.uint8("mototrbo.command", "Command", base.HEX, vs_command)
local f_source = ProtoField.uint32("mototrbo.source", "Source", base.DEC)
local f_reg_flags = ProtoField.uint64("mototrbo.Registration.flags", "Flags", base.HEX)
local f_link_type = ProtoField.uint8("mototrbo.linktype", "Link Type", base.DEC, vs_linktype)
local f_link_version = ProtoField.uint8("mototrbo.linkver", "Link Version", base.DEC)
local f_peer_count = ProtoField.uint16("mototrbo.peercount", "Peer Count", base.DEC)
local f_length = ProtoField.uint16("mototrbo.length", "Length", base.DEC)
local f_peer_id = ProtoField.uint32("mototrbo.peers.id", "Radio ID", base.DEC)
local f_peer_ip = ProtoField.ipv4("mototrbo.peers.ip", "Radio IP")
local f_peer_port = ProtoField.uint16("mototrbo.peers.port", "Radio Port", base.DEC)
local f_peer_mode = ProtoField.uint8("mototrbo.peers.mode", "Radio Mode", base.HEX)
local data_dis = Dissector.get("data")

p_moto.fields = { f_command, f_source, f_reg_flags, f_link_type, f_link_version, f_peer_count, f_length, f_peer_id, f_peer_ip, f_peer_port, f_peer_mode }

function p_moto.dissector(buf, pkt, tree)
	local subtree = tree:add(p_moto, buf())
	local cmd = buf(0,1):uint()
	local cmdTree = subtree:add(f_command, buf(0,1))	
	subtree:add(f_source, buf(1,4))	
	if cmd == 0x70 then
		local dissector = Dissector.get("xnl")
		if dissector == nil then
			-- fallback dissector that just shows the raw data.
		        data_dis:call(buf(5):tvb(), pkt, tree)
		else
			dissector:call(buf(5):tvb(), pkt, tree)
		end
	elseif cmd == 0x90 then	
		subtree:add(f_reg_flags, buf(5,5))
		subtree:add(f_link_type, buf(10,1))
		subtree:add(f_link_version, buf(11,1))
		subtree:add(f_link_type, buf(12,1))
		subtree:add(f_link_version, buf(13,1))
	elseif cmd == 0x91 then
		subtree:add(f_reg_flags, buf(5,5))
		subtree:add(f_peer_count, buf(10,2))
		subtree:add(f_link_type, buf(12,1))
		subtree:add(f_link_version, buf(13,1))
		subtree:add(f_link_type, buf(14,1))
		subtree:add(f_link_version, buf(15,1))
	elseif cmd == 0x93 then
		subtree:add(f_length, buf(5,2))
		local length = buf(5,2):uint()
		local count = length/11
		local peer_tree = subtree:add("Peers")
		for i=0,count-1,1 do
			local peer = peer_tree:add(f_peer_id, buf(7+(i*11),4))
			peer:add(f_peer_ip, buf(11+(i*11),4))
			peer:add(f_peer_port, buf(15+(i*11),2))
			peer:add(f_peer_mode, buf(17+(i*11),1))
		end
	elseif cmd == 0x94 then
		subtree:add(f_link_type, buf(5,1))
		subtree:add(f_link_version, buf(6,1))
		subtree:add(f_link_type, buf(7,1))
		subtree:add(f_link_version, buf(8,1))
	elseif cmd == 0x95 then
		subtree:add(f_link_type, buf(5,1))
		subtree:add(f_link_version, buf(6,1))
		subtree:add(f_link_type, buf(7,1))
		subtree:add(f_link_version, buf(8,1))
	elseif cmd == 0x98 then
		subtree:add(f_reg_flags, buf(5,5))
	elseif cmd == 0x99 then
		subtree:add(f_reg_flags, buf(5,5))
	else
		print("Unknown command: " .. buf(0,1))
		-- fallback dissector that just shows the raw data.
	        data_dis:call(buf(5):tvb(), pkt, tree)
	end
	if vs_commands[cmd] == nil then
		subtree:append_text(", Command: 0x" .. string.format("%02X", cmd))
	else
		subtree:append_text(", Command: " .. vs_commands[cmd])
		-- This doesn't work automatically for some reason...
		cmdTree:set_text("Command: " .. vs_commands[cmd] .. " (0x" .. string.format("%02X", cmd) .. ")")
	end
end

local udp_encap_table = DissectorTable.get("udp.port")

udp_encap_table:add(50000, p_moto)
