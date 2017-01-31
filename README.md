# lua-ffi-yara
Lua bindings to an opaque Yara wrapper

##Description
This library provides an opaque wrapper and Lua FFI bindings to the Yara malware
scanning library. Yara's C API provides an event-based model to examine the
result of scanning files or memory buffers against a set of compiled rules,
using a callback to examine the result of each rule's execution. This push-
style design is detrimentally slow in Lua FFI environments, and is explicitly
warned against (see <http://luajit.org/ext_ffi_semantics.html>). For this
reason, a simple wrapper that does not rely in a Lua-land callback is provided;
this can be loaded via FFI and integrated in Lua FFI/LuaJIT environments.

##Installation

A Makefile is provided to build the C wrapper:

```
	~/lua-ffi-yara$ make
```

The build produces a single shared object, `libyawrap.so`, that can be loaded
dynamically into an OpenResty environment.

The Yara library must be built and installed on the target system. Compile Yara
from source using the configure flag `--with-pic`. The static archive
`libyara.a` must be available as part of the source.

##Usage

Integration into OpenResty environments is straightforward through the included
`lib/yara.lua` library. Two functions are exported to inspect either a file path
(useful for buffered request or response bodies), or strings (converted to
memory buffers by the library).

```lua
	init_by_lua_block {
		local yara = require "yara"
		yara.load("/path/to/libyawrap.so") -- this is built in the "src" dir
	}

	access_by_lua_block {
		local yara = require "yara"

		local messages = {} -- table to hold matched rule data
		local rulepath = "/path/to/compiled/yara.rules" -- compiled yara rules

		ngx.req.read_body()
		local body = ngx.req.get_body_file()

		local matched = yara.inspect_file(body, rulepath, messages)

		if matched then
			for i, rule_name in ipairs(matches) do
				ngx.say(rule_name)
			end
		end
	}
```

For performance reasons, Yara rules should be precompiled and saved on-disk to
pass into the wrapper. Rules can be precompiled with the `yarac` utility.

###Functions

####yara.load

**syntax**: *yara.load(path)*

Load the `yawrap.so` library. This must be called before accessing any wrapper
functions.

####yara.inspect_file

**syntax**: *matched = yara.inspect_file(path, ruleset, matches?)*

Scan the file located at `path` using the precompiled Yara ruleset found at
the path `ruleset`. Returns true if any matches are found, or false otherwise.
Additionally, an optional table `matches` can be provided to hold names of each
rule that matched the target path.

####yara.inspect_string

**syntax**: *matched = yara.inspect_string(str, ruleset, matches?)*

Similar to `inspect_file`, but accepts a Lua string to examine as a memory
buffer instead of a file path.

##License

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>

##Bugs

Please report bugs by creating a ticket with the GitHub issue tracker.
