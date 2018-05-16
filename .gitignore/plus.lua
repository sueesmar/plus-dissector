-- Wireshark dissector for PLUS (Path Layer UDP Substrate)
-- Author: Marcel Sueess, ZHAW, sueesmar@students.zhaw.ch
-- Inspired by: Hadriel Kaplan <hadrielk at yahoo dot com> from https://wiki.wireshark.org/Lua/Examples
-- Date: 01.04.2018
-- Version: 0.2

-- Constants
local PLUS_BASIC_HEADER_LEN = 20 -- in bytes
local PLUS_EXTENDED_HEADER_LEN_MIN = 22 -- in bytes

-- Declare the Protocol
plus_proto = Proto("plus","Path Layer UDP Substrate");

-- Integrity Indication values
local pcfii_part = {
    [0] = "PCF value not integrity protected",
    [1] = "PCF value first quarter integrity protected",
    [2] = "PCF value first half integrity protected",
    [3] = "PCF value full integrity protected",
}   

-- Declare the protocol fields
-- ProtoField.new(name, abbr, type, [valuestring], [base], [mask], [descr]))
local pf_magic_id = ProtoField.new("Magic ID", "plus.magic_id", ftypes.UINT32, nil, base.HEX, 0xFFFFFFF0, "Magic ID of the PLUS Protocol")
local pf_flags = ProtoField.new("Flags", "plus.flags", ftypes.UINT8, nil, base.HEX, 0x0F, "Flags of PLUS")
local pf_cat = ProtoField.new("CAT", "plus.cat", ftypes.UINT64, nil, base.DEC, nil, "Connection/Association Token for the PLUS association")
local pf_psn = ProtoField.new("PSN", "plus.psn", ftypes.UINT32, nil, base.DEC, nil, "Packet Serial Number")
local pf_pse = ProtoField.new("PSE", "plus.pse", ftypes.UINT32, nil, base.DEC, nil, "Packet Serial Echo")
local pf_pcftype = ProtoField.new("PCF Type", "plus.pcftype", ftypes.UINT8, nil, base.DEC, nil, "Path Communication Function Type")
local pf_pcflength = ProtoField.new("PCF Length", "plus.pcflength", ftypes.UINT8, nil, base.DEC, 0xFC, "Path Communication Function Length")
local pf_pcfii = ProtoField.new("PCF Integrity Indication", "plus.pcfii", ftypes.UINT8, pcfii_part, base.HEX, 0x03, "Path Communication Function Integritiy Indication")
local pf_pcfvalue = ProtoField.new("PCF Value", "plus.pfcvalue", ftypes.BYTES, nil, base.NONE, nil, "Path Communication Value")
local pf_data = ProtoField.new("Data", "plus.data", ftypes.BYTES, nil, base.NONE, nil, "Data of higher layer")

-- within the flags field, we want to parse/show the bits separately
-- note the "base" argument becomes the size of the bitmask'ed field when ftypes.BOOLEAN is used
-- the "mask" argument is which bits we want to use for this field (e.g., base=16 and mask=0x8000 means we want the top bit of a 16-bit field)
local pf_flag_lola = ProtoField.new("LoLa Flag", "plus.flags.lola", ftypes.BOOLEAN, nil, 4, 0x08, "Latency sensitive when set.")
local pf_flag_roi = ProtoField.new("RoI Flag", "plus.flags.roi", ftypes.BOOLEAN, nil, 4, 0x04, "Not sensitive to reordering when set.")
local pf_flag_stop = ProtoField.new("Stop Flag", "plus.flags.stop", ftypes.BOOLEAN, nil, 4, 0x02, "Stop the association when set.")
local pf_flag_extended = ProtoField.new("Extended Header Flag", "plus.flags.extended", ftypes.BOOLEAN, nil, 4, 0x01, "Extended header follows when set.")


-- this actually registers the ProtoFields above, into our new Protocol
-- in a real script I wouldn't do it this way; I'd build a table of fields programmatically
-- and then set plus_proto.fields to it, so as to avoid forgetting a field
plus_proto.fields = {pf_magic_id, pf_flags, pf_flag_lola, pf_flag_roi, pf_flag_stop, pf_flag_extended, pf_cat, pf_psn, pf_pse, pf_pcftype, pf_pcflength, pf_pcfii, pf_pcfvalue, pf_data};

-- we don't just want to display our protocol's fields, we want to access the value of some of them too!
-- There are several ways to do that.  One is to just parse the buffer contents in Lua code to find
-- the values.  But since ProtoFields actually do the parsing for us, and can be retrieved using Field
-- objects, it's kinda cool to do it that way. So let's create some Fields to extract the values.
-- The following creates the Field objects, but they're not 'registered' until after this script is loaded.
-- Also, these lines can't be before the 'plus_proto.fields = ...' line above, because the Field.new() here is
-- referencing fields we're creating, and they're not "created" until that line above.
-- Furthermore, you cannot put these 'Field.new()' lines inside the dissector function.
-- Before Wireshark version 1.11, you couldn't even do this concept (of using fields you just created).
local cat_field = Field.new("plus.cat") -- access the value with cat_field()()
local lola_field = Field.new("plus.flags.lola")
local roi_field = Field.new("plus.flags.roi")
local stop_field = Field.new("plus.flags.stop")
local extended_field = Field.new("plus.flags.extended")
local length_field = Field.new("plus.pcflength")

-- Function for dissect the protocol
function plus_proto.dissector(tvbuf,pinfo,root_tree)
    -- Set protocol name in column
    pinfo.cols.protocol = "PLUS"

    -- We want to check that the packet size is rational during dissection, so let's get the length of the
    -- packet buffer (Tvb).
    -- we can use tvb:len() or tvb:reported_len() here; but I prefer tvb:reported_length_remaining() as it's safer.
    local pktlen = tvbuf:reported_length_remaining()
    
    -- We start by adding our protocol to the dissection display tree.
    -- A call to tree:add() returns the child created, so we can add more "under" it using that return value.
    -- The second argument is how much of the buffer/packet this added tree item covers/represents - in this
    -- case (plus protocol) that's the remainder of the packet.
    local plus_tree = root_tree:add(plus_proto, tvbuf:range(0,pktlen))

    -- Add the first field (magic id) to the tree
    plus_tree:add(pf_magic_id, tvbuf:range(0,4))
    
    -- for our flags field, we want a sub-tree
    local flag_tree = plus_tree:add(pf_flags, tvbuf:range(3,1))
    -- I'm indenting this for clarity, because it's adding to the flag's child-tree
        flag_tree:add(pf_flag_lola, tvbuf:range(3,1))
        flag_tree:add(pf_flag_roi, tvbuf:range(3,1))
        flag_tree:add(pf_flag_stop, tvbuf:range(3,1))
        flag_tree:add(pf_flag_extended, tvbuf:range(3,1))

    plus_tree:add(pf_cat, tvbuf:range(4,8))
    plus_tree:add(pf_psn, tvbuf:range(12,4))
    plus_tree:add(pf_pse, tvbuf:range(16,4))

    -- We'd like to put the CAT in the GUI row for this packet, in its
    -- INFO column/cell.  First we need the CAT value, though.  Since we just
    -- dissected it with the previous code line, we could now get it using a Field's
    -- FieldInfo extractor, but instead we'll get it directly from the TvbRange just
    -- to show how to do that.  We'll use Field/FieldInfo extractors later on...
    local cat = tvbuf:range(4,8)
    local psn = tvbuf:range(12,4):uint()
    local pse = tvbuf:range(16,4):uint()

    -- Print the infos in the info column
    pinfo.cols.info:set("CAT: ".. cat_field()() ..", PSN: " .. psn .. ", PSE: " .. pse)

    -- If extended bit is set, print dissect extended header
    if extended_field()() then
        -- print extended header
        plus_tree:add(pf_pcftype, tvbuf:range(20,1))
        plus_tree:add(pf_pcflength, tvbuf:range(21,1))
        plus_tree:add(pf_pcfii, tvbuf:range(21,1))
        plus_tree:add(pf_pcfvalue, tvbuf:range(22,length_field()()))
        plus_tree:add(pf_data, tvbuf:range(22+length_field()(),pktlen-(PLUS_EXTENDED_HEADER_LEN_MIN+length_field()())))
    else
        -- basic header, so print data
        plus_tree:add(pf_data, tvbuf:range(20,pktlen-PLUS_BASIC_HEADER_LEN))
    end
end

-- load the udp.port table
udp_table = DissectorTable.get("udp.port")
-- register our protocol to handle udp port 9999
udp_table:add(9999,plus_proto)

-- we also want to add the heuristic dissector, for any UDP protocol
-- first we need a heuristic dissection function
-- this is that function - when wireshark invokes this, it will pass in the same
-- things it passes in to the "dissector" function, but we only want to actually
-- dissect it if it's for us, and we need to return true if it's for us, or else false
-- figuring out if it's for us or not is not easy in general
-- we need to try as hard as possible, or else we'll think it's for us when it's
-- not and block other heuristic dissectors from getting their chance
--
-- Note: this heuristic stuff is new in 1.11.3
local function heur_dissect_plus(tvbuf,pktinfo,root_tree)

    -- Check if the header has minimum length
    if tvbuf:len() < PLUS_BASIC_HEADER_LEN then
        return false
    end

    -- To use the bitfield() function later, we have to generate this object.
    local tvbr = tvbuf:range(0,pktlen)

    -- the first 28 bits are the magic id, which has to be 0xd8007ff (226494463 in decimal)
    local check_magic_id = tvbr:bitfield(0,28)
    -- debug("check_magic_id:" .. check_magic_id) -- to print the variable to console
    if not (check_magic_id == 0xd8007ff) then
        return false
    end

    -- ok, looks like it's ours, so go dissect it
    -- note: calling the dissector directly like this is new in 1.11.3
    -- also note that calling a Dissector object, as this does, means we don't
    -- get back the return value of the dissector function we created previously
    -- so it might be better to just call the function directly instead of doing
    -- this
    plus_proto.dissector(tvbuf,pktinfo,root_tree)

    -- since this is over a transport protocol, such as UDP, we can set the
    -- conversation to make it sticky for our dissector, so that all future
    -- packets to/from the same address:port pair will just call our dissector
    -- function directly instead of this heuristic function
    -- this is a new attribute of pinfo in 1.11.3
    -- we have to restart the capture, if the magic id changes, but port not,
    -- otherwise wireshark holds this conversation
    pktinfo.conversation = plus_proto

    return true
end

-- now register that heuristic dissector into the udp heuristic list
plus_proto:register_heuristic("udp",heur_dissect_plus)