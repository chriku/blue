#!/bin/sh
OLD_PWD=$PWD
if [ ! -f "./LuaFormatter/lua-format" ]; then
  cd LuaFormatter
  cmake .
  make -j4
  cd $OLD_PWD
fi
./LuaFormatter/lua-format -c format.yml -i *.lua */*.lua

