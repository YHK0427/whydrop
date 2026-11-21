-- whydrop WD (UDP) and WT (TCP) dissector for Wireshark >= 3.6.
-- Field names follow docs/protocol.md. The MAC is shown as bytes and never verified (the secret isn't here).
-- Install: copy this file to your personal Lua plugins folder (Help > About Wireshark > Folders), restart.
-- Default port 48100; change it in Preferences > Protocols > WHYDROP.

local p = Proto("whydrop", "whydrop wire protocol")

local WD_TYPES = { [1] = "PROBE", [2] = "ECHO", [3] = "NAT_REQ", [4] = "NAT_REPLY" }
local WT_TYPES = { [1] = "NONCE", [2] = "HELLO", [3] = "HELLO_OK", [4] = "AUTH_FAIL", [5] = "VERSION", [6] = "BUSY" }
local WT_SIZES = { [1] = 20, [2] = 30, [3] = 16, [4] = 4, [5] = 4, [6] = 4 }
local ROLES = { [1] = "hot", [2] = "idle", [3] = "nat" }
local FRAMES = { [0x10] = "HB", [0x11] = "HB_ACK", [0x20] = "IDLE_PING", [0x21] = "IDLE_PONG", [0x30] = "NAT_PROBE" }

local f = {
  wd_magic = ProtoField.string("whydrop.wd.magic", "Magic"),
  wd_version = ProtoField.uint8("whydrop.wd.version", "Version"),
  wd_type = ProtoField.uint8("whydrop.wd.type", "Type", base.DEC, WD_TYPES),
  wd_session = ProtoField.uint32("whydrop.wd.session_id", "Session ID", base.HEX),
  wd_seq = ProtoField.uint32("whydrop.wd.seq", "Seq"),
  wd_tsend = ProtoField.uint64("whydrop.wd.t_send_ns", "Agent send time (ns, monotonic)"),
  wd_rc = ProtoField.uint32("whydrop.wd.recv_count", "Receive count"),
  wd_epoch = ProtoField.uint32("whydrop.wd.epoch", "Reflector epoch", base.HEX),
  wd_bitmap = ProtoField.uint32("whydrop.wd.rx_bitmap", "Receive bitmap", base.HEX),
  wd_arg = ProtoField.uint32("whydrop.wd.arg", "Arg"),
  wd_hmac = ProtoField.bytes("whydrop.wd.hmac", "HMAC-8 (not verified)"),

  wt_magic = ProtoField.string("whydrop.wt.magic", "Magic"),
  wt_version = ProtoField.uint8("whydrop.wt.version", "Version"),
  wt_type = ProtoField.uint8("whydrop.wt.type", "Type", base.DEC, WT_TYPES),
  wt_nonce = ProtoField.bytes("whydrop.wt.nonce", "Nonce"),
  wt_role = ProtoField.uint8("whydrop.wt.role", "Role", base.DEC, ROLES),
  wt_session = ProtoField.uint32("whydrop.wt.session_id", "Session ID", base.HEX),
  wt_param = ProtoField.uint32("whydrop.wt.param_s", "Param (s)"),
  wt_anonce = ProtoField.bytes("whydrop.wt.anonce", "Agent nonce"),
  wt_epoch = ProtoField.uint32("whydrop.wt.epoch", "Reflector epoch", base.HEX),
  wt_hmac = ProtoField.bytes("whydrop.wt.hmac", "HMAC-8 (not verified)"),

  fr_type = ProtoField.uint8("whydrop.frame.type", "Frame type", base.HEX, FRAMES),
  fr_flags = ProtoField.uint8("whydrop.frame.flags", "Flags", base.HEX),
  fr_seq = ProtoField.uint32("whydrop.frame.seq", "Seq"),
  fr_tsend = ProtoField.uint64("whydrop.frame.t_send_ns", "Send time (ns, monotonic)"),
}
p.fields = {}
for _, v in pairs(f) do table.insert(p.fields, v) end

p.prefs.port = Pref.uint("Port", 48100, "UDP and TCP port of the reflector")

local function dissect_wd(buf, pinfo, tree)
  if buf:len() ~= 44 or buf(0, 2):string() ~= "WD" then return 0 end
  pinfo.cols.protocol = "WHYDROP"
  local t = buf(3, 1):uint()
  local st = tree:add(p, buf(), "whydrop WD " .. (WD_TYPES[t] or "?"))
  st:add(f.wd_magic, buf(0, 2)); st:add(f.wd_version, buf(2, 1)); st:add(f.wd_type, buf(3, 1))
  st:add(f.wd_session, buf(4, 4)); st:add(f.wd_seq, buf(8, 4)); st:add(f.wd_tsend, buf(12, 8))
  st:add(f.wd_rc, buf(20, 4)); st:add(f.wd_epoch, buf(24, 4)); st:add(f.wd_bitmap, buf(28, 4))
  st:add(f.wd_arg, buf(32, 4)); st:add(f.wd_hmac, buf(36, 8))
  local info = string.format("WD %s seq=%d", WD_TYPES[t] or "?", buf(8, 4):uint())
  if t == 2 then info = info .. string.format(" rc=%d", buf(20, 4):uint()) end
  if t == 3 or t == 4 then info = info .. string.format(" arg=%d", buf(32, 4):uint()) end
  pinfo.cols.info = info
  return 44
end

local function dissect_wt(buf, pinfo, tree)
  local off, infos = 0, {}
  local len = buf:len()
  pinfo.cols.protocol = "WHYDROP"
  while off < len do
    if len - off >= 4 and buf(off, 2):string() == "WT" then
      local t = buf(off + 3, 1):uint()
      local n = WT_SIZES[t]
      if not n or len - off < n then break end
      local st = tree:add(p, buf(off, n), "whydrop WT " .. (WT_TYPES[t] or "?"))
      st:add(f.wt_magic, buf(off, 2)); st:add(f.wt_version, buf(off + 2, 1)); st:add(f.wt_type, buf(off + 3, 1))
      if t == 1 then st:add(f.wt_nonce, buf(off + 4, 16))
      elseif t == 2 then
        st:add(f.wt_role, buf(off + 4, 1)); st:add(f.wt_session, buf(off + 6, 4)); st:add(f.wt_param, buf(off + 10, 4))
        st:add(f.wt_anonce, buf(off + 14, 8)); st:add(f.wt_hmac, buf(off + 22, 8))
        table.insert(infos, string.format("WT HELLO role=%s", ROLES[buf(off + 4, 1):uint()] or "?"))
      elseif t == 3 then st:add(f.wt_epoch, buf(off + 4, 4)); st:add(f.wt_hmac, buf(off + 8, 8)) end
      if t ~= 2 then table.insert(infos, "WT " .. (WT_TYPES[t] or "?")) end
      off = off + n
    elseif len - off >= 16 and FRAMES[buf(off, 1):uint()] then
      local t = buf(off, 1):uint()
      local st = tree:add(p, buf(off, 16), "whydrop frame " .. FRAMES[t])
      st:add(f.fr_type, buf(off, 1)); st:add(f.fr_flags, buf(off + 1, 1))
      st:add(f.fr_seq, buf(off + 4, 4)); st:add(f.fr_tsend, buf(off + 8, 8))
      table.insert(infos, string.format("WT %s seq=%d", FRAMES[t], buf(off + 4, 4):uint()))
      off = off + 16
    else
      break
    end
  end
  if #infos > 0 then pinfo.cols.info = table.concat(infos, ", ") end
  return off
end

local udp_dissector = Proto("whydrop_udp", "whydrop WD")
function udp_dissector.dissector(buf, pinfo, tree) return dissect_wd(buf, pinfo, tree) end
local tcp_dissector = Proto("whydrop_tcp", "whydrop WT")
function tcp_dissector.dissector(buf, pinfo, tree) return dissect_wt(buf, pinfo, tree) end

local current
local function register()
  if current then
    DissectorTable.get("udp.port"):remove(current, udp_dissector)
    DissectorTable.get("tcp.port"):remove(current, tcp_dissector)
  end
  current = p.prefs.port
  DissectorTable.get("udp.port"):add(current, udp_dissector)
  DissectorTable.get("tcp.port"):add(current, tcp_dissector)
end
function p.prefs_changed() register() end
register()

-- UDP on any port too: 44 bytes starting with "WD" version 1
local function heuristic(buf, pinfo, tree)
  if buf:len() == 44 and buf(0, 2):string() == "WD" and buf(2, 1):uint() == 1 then
    dissect_wd(buf, pinfo, tree)
    return true
  end
  return false
end
p:register_heuristic("udp", heuristic)
