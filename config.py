#!/usr/bin/env python
# -*- coding: utf-8 -*-

from tornado.options import define, options, parse_command_line


define("port", default = 8888, help = "run on the given port", type = int)
define("debug", default = True, help = "run in debug mode")
define("secret_key", default = "Secretkey", help = "The key which encode your token") # TODO 重启服务时随机生成
