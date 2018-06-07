#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# coding=utf-8

from mwsapi import v3

key="YOUR API KEY"
mws=v3(key, "public")

print ("# StartTesting File API")
print ("# Testing file.download")
with open("4020ce0de0cc206f9bc241e5634a02da", "wb") as fd:
	fd.write(mws.file.download("4020ce0de0cc206f9bc241e5634a02da"))
print ("Passed")

print ("# Testing file.upload")
assert mws.file.upload("4020ce0de0cc206f9bc241e5634a02da")
print ("Passed")

print ("# Testing file.mwsinfo")
assert mws.file.mwsinfo("4020ce0de0cc206f9bc241e5634a02da")
print ("Passed")

print ("# Testing file.behaviorinfo")
assert mws.file.behaviorinfo("4020ce0de0cc206f9bc241e5634a02da")
print ("Passed")

print ("# Testing file.staticinfo")
assert mws.file.staticinfo("4020ce0de0cc206f9bc241e5634a02da")
print ("Passed")

print ("# Testing file.addinfo")
assert mws.file.addinfo("4020ce0de0cc206f9bc241e5634a02da")
print ("Passed")

print ("# StartTesting URL API")
print ("# Testing url.request")
assert mws.url.request("https://www.malwares.com")
print ("Passed")

print ("# Testing url.info")
assert mws.url.info("https://www.malwares.com")
print ("Passed")

print ("# StartTesting IP API")
print ("# Testing ip.info")
assert mws.ip.info("8.8.8.8")
print ("Passed")

print ("# StartTesting Hostname API")
print ("# Testing hostname.info")
assert mws.hostname.info("www.malwares.com")
print ("Passed")

print ("# StartTesting Tag API")
print ("# Testing tag.search")
assert mws.tag.search("ransomware")
print ("Passed")

print ("# Testing tag.search, with start time")
assert mws.tag.search("ransomware", start="2018-06-05 00:00:00")
print ("Passed")

