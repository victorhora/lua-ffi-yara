local _M = {}

local ffi = require "ffi"
ffi.cdef[[
void free(void* p);

typedef struct yawrap_match_s {
    char *msg;
    struct yawrap_match_s* next;
} yawrap_match_t;

typedef struct yarawrap_user_data_s {
    unsigned int count:7;
    unsigned int multi_cap:1;
    yawrap_match_t* head;
} yawrap_user_data_t;

int scan_mem_wrapper(const char* compiled_rules_path, uint8_t* buffer,
    size_t length, yawrap_user_data_t* user_data);
int scan_file_wrapper(const char* compiled_rules_path,
    const char* scan_file_path, yawrap_user_data_t* user_data);
]]

local lib
local ud_type = ffi.typeof("yawrap_user_data_t[1]")
local match_type = ffi.typeof("yawrap_match_t[1]")

local ERROR_SUCCESS = 0

local function inspect(content, is_memory, ruleset, matches)
  matches = type(matches) == 'table' and matches or {}

  local ud_ref = ffi.new(ud_type) -- this ref is gc managed, we dont need to free it later
  local user_data = ud_ref[0] -- get a 'pointer' to the first user_data struct
  user_data.multi_cap = 1 -- try to search for multiple matches

  local matched = false

  local res

  -- if we had a memory buffer, cast it appropriately
  -- otherwise, we can just give yara the disk-buffered path
  -- containing the request body payload
  if is_memory then
    local buf = ffi.cast("uint8_t *", content)
    res = lib.scan_mem_wrapper(ruleset, buf, #content, user_data)
  else
    res = lib.scan_file_wrapper(ruleset, content, user_data)
  end

  if res ~= ERROR_SUCCESS then
    ngx.log(ngx.WARN, "error when processing yara: " .. res)
	return false
  end

  -- we had a match, walk the list, logging and freeing each match
  if user_data.count > 0 then
    matched = true

    local match_ptr = user_data.head

    -- tmp pointer so we can free each element in the list
    local tmp_ref = ffi.new(match_type)
    local tmp = tmp_ref[0]

    while true do
      table.insert(matches, ffi.string(match_ptr.msg))

      -- free the msg ptr in the match, then free the match itself
      ffi.C.free(match_ptr.msg)
      tmp = match_ptr
      match_ptr = match_ptr.next
      ffi.C.free(tmp)

      if match_ptr == nil then break end
    end
  end

  return matched
end

function _M.inspect_file(path, ruleset, matches)
	return inspect(path, false, ruleset, matches)
end

function _M.inspect_string(str, ruleset, matches)
	return inspect(str, true, ruleset, matches)
end

function _M.load(path)
	local ok, err = pcall(function() lib = ffi.load(path) end)

	if not ok then
		ngx.log(ngx.WARN, err)
	end
end

_M.version = "0.1"

return _M
