# lua-shadowsocks

A shadowsocks client in Lua, based on libuv through my binding lua-xuv.

## Features

* It's written in Lua so it is tiny.
* Automated direct or shadowsocks proxying...
* Builtin transparent proxying (only on Linux, 127.0.0.1:2336)
* HTTP CONNECT proxy (to be finished)
* Detects GFW behaviour and let the user decide if we need to proxy it.
* 内置绿爸，为绿色上网保驾护航！

## How to deploy?

### Windows

Extract the win-runtime.zip and in command prompt execute "luajit Shadowsocks.lua server_ip [server_port]".

### Linux

Install LuaJIT (download it from luajit.org, tar xf then make, sudo make install)
Build LuaCrypto and lua-xuv (https://github.com/imzyxwvu/lua-xuv)
Open a screen session and "luajit Shadowsocks.lua server_ip [server_port]"
