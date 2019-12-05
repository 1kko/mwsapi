#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# coding=utf-8


"""Malwares.com API
Python wrapper for Malwares.com API - by ikko
Github Repository: https://github.com/1kko/mwsapi
complete api documentation: https://www.malwares.com/about/api

Usage: 
	from mwsapi import v3
	mws=api(api_key="yourapikey", api_type="public")
	result=mws.file.mwsinfo("4020ce0de0cc206f9bc241e5634a02da")
	print result

Available Methods:
	file.upload
	file.download
	file.mwsinfo
	file.behaviorinfo
	file.staticinfo
	file.addinfo
	url.request
	url.info
	ip.info
	hostname.info
	tag.search

Not Supported:
	bulk apis
"""


from datetime import datetime
import os, re, json, urlparse

# pip install requests
import requests

# pip install python-dateutil
from dateutil import parser

# pip install urllib3
import urllib3


#urllib3.disable_warnings()

class v3():
	def __init__(self, api_key, api_type):

		self.api_key=api_key
		self.api_type=api_type.strip().lower()

		self.api_type="public"
		if api_type == "private":
			self.api_type="private"
		self.baseURL="https://"+self.api_type+".api.malwares.com/v3/"

		self.file=self._file(self.api_key, self.api_type, self.baseURL)
		self.url=self._url(self.api_key, self.api_type, self.baseURL)
		self.ip=self._ip(self.api_key, self.api_type, self.baseURL)
		self.hostname=self._hostname(self.api_key, self.api_type, self.baseURL)
		self.tag=self._tag(self.api_key, self.api_type, self.baseURL)

	class _file:
		def __init__(self, api_key, api_type, baseURL):
			self.api_key=api_key
			self.api_type=api_type
			self.baseURL=urlparse.urljoin(baseURL,"file/")

		def upload(self, filePath, secure=1):
			""" Upload File for analysis
			Max upload file size is 200MB.

			Args:
				filePath (str) : Target File path
				secure(int): 1 = Make this upload to private.
				             0 = Make this upload to public.

			Returns:
				json: json results

			Return Example:
				{
				  "result_code": "Result Code (Number)",
				  "result_msg": "Result Message (String)",
				  "version": "API Page Version (String)",
				  "date": "date time of API request (String)",
				  "md5": "MD5 Hash value of the object (String)",
				  "sha1": "SHA1 hash value of the object (String)",
				  "sha256": "SHA256 Hash value of the Object (String)"
				}

			"""
			if self.api_type=="public" and secure==1:
				# secure option is only for private
				secure=0
			fileName=os.path.basename(filePath)

			url=urlparse.urljoin(self.baseURL, "upload/")
			param={'api_key':self.api_key, 'filename':fileName, 'secure':secure}
			files={"file":(fileName, open(filePath,"rb"))}
			
			return requests.post(url, files=files, data=param)

		def mwsinfo(self, hashValue):
			"""File Summary Report Request
			Get summary information.

			Args:
				hashValue (str) : File Hash (MD5, SHA1, SHA256)

			Returns:
				json: json results

			Return Example:
				{
				  "result_code": "Result Code (Number)",
				  "result_msg": "Result Message (String)",
				  "version": "API page version (String)",
				  "date": "date time of API request (String)",
				  "md5": "MD5 Hash value of the object (String)",
				  "sha1": "SHA1 Hash value of the object (String)",
				  "sha256": "SHA256 Hash value of the file (String)",
				  "view_count": "file lookup count (Number)",
				  "black_white": "Black/White List. 1 is Black and 2 is White list (Number)",
				  "filetype": "File format (String)",
				  "filesize": "File size (Number)",
				  "first_seen": "First collected date of the file (String)",
				  "ai_score": "result value created by MAX AI (Number)",
				  "taglist": "Tag name list of the file (Array)",
				  "tag_name_etc" : "Profiling Tag list of files (Array)", 
				  "imphash" : "Import Table-based Hashes of PE type of files (String)",
				  "ssdeep" : "ssdeep-based Hashes of files (String)",
				  "behavior": {
				      "Behavior analysis environment" : 
				      {
				        "date" : "behavior analysis data (String)",
				        "detection" : "detected malicious behavior list (Array)",
				        "security_level" : "Behavior Risk. 1 is malicious, 2 is dangerous, 3 is normal (Number)"
				      }
				    }
				}
			"""
			url=urlparse.urljoin(self.baseURL, "mwsinfo")
			param={'api_key':self.api_key, 'hash':hashValue}
		
			response=requests.get(url, param)
			return response.json()

		def behaviorinfo(self, hashValue):
			"""File Behavior Request
			Get Behavior analysis report.

			Args:
				hashValue (str) : File Hash (MD5, SHA1, SHA256)

			Returns:
				json: json results

			Return Example:
			{
			  "result_code": "Result Code (Number)",
			  "result_msg": "Result Message (String)",
			  "version": "API page version (String)",
			  "date": "date time of API request (String)",
			  "md5": "MD5 hash value of the object (String)",
			  "sha1": "SHA1 hash value of the object (String)",
			  "sha256": "SHA256 Hash value of the object (String)",
			  "view_count": "file lookup count (Number)",
			  "black_white": "Determines black/white listed. 1=blacklisted, 2=whitelisted (Number)",
			  "filetype": "type of the file (String)",
			  "filesize": "size of the file (Number)",
			  "first_seen": "fist date file has collected (String)",
			  "ai_score": "score by MAX AI (Number)",
			  "taglist": "List of tags of the file (Array)",
			  "tag_name_etc" : "List of profiling tags of the file (Array)", 
			  "imphash" : "Hash value of Import Table on PE type files (String)",
			  "ssdeep" : "Hash value of ssdeep result (String)",
			  "behavior": {
			    "analysis enviroment": {
			      "date": "date time of analysis (String)",
			      "detection": "list of malicious activity (Array)",
			      "security_level": "Risk level of the result. 1=malicious, 2=dangerous, 3=normal (Number)"
			    }
			  }
			}
			"""
			url=urlparse.urljoin(self.baseURL, "behaviorinfo")
			param={'api_key':self.api_key, 'hash':hashValue}

			response=requests.get(url, param)
			return response.json()

		def staticinfo(self, hashValue):
			""" File Static Report Request
			Get static analysis report.

			Args:
				hashValue (str) : File Hash (MD5, SHA1, SHA256)

			Returns:
				json: json results

			Return Example:
				{
				  "result_code": "Result Code (Number)",
				  "result_msg": "Result Message (String)",
				  "version": "API page version (String)",
				  "date": "date time of API request (String)",
				  "md5": "MD5 Hash value of the Object (String)",
				  "sha1": "SHA1 hash value of the object (String)",
				  "sha256": "SHA256 Hash value of the object (String)",
				  "format_type" :  "Result type of static analyis (String)",
				  "peinfo" : {
				    "version": "version of peinfo result format (String)",
				    "date": "date time of run execution peinfo (String)",
				    "section_info" : [
				      {
				        "raw_data_hash" : "SHA256 value of the section data (String)",
				        "raw_data_offset" : "Offset to the section in file (String)",
				        "section_name" : "Section name(String)"
				      }
				    ],
				    "pe_info" : [
				      {
				        "subsystem" : "subsystem (String)",
				        "is_windows_gui" : "GUI type of Windows (String)",
				        "image_base" : "base address of memory allocation (String)",
				        "characteristics" : "attributes of file (String)",
				        "pe_file_type" : "Type of PE file(String)",
				        "stored_checksum" : "Checksum of file (String)",
				        "file_alignment" : "Chunk Size of the section in file (String)",
				        "entry_point" : "Entry point of the program (String)",
				        "is_console" : "is this the console program (String)",
				        "section_alignment" : "Chuck Size of the section in virtual memory (String)"
				      }
				    ],
				    "signcheck" : {
				      "signing_date" : "date time of code sign (String)",
				      "signers_details" : "list of code sign certificates (Array)",
				      "verified" : "result of verification on code sign certificates (String)",
				      "counter_signers_details" : "list of timestamp certificates (Array)"
				    },
				    "import_info" : [
				      {
				        "dll_name" : "list DLLs that are imported (String)",
				        "function_list" : "list of functions used (Array)"
				      }
				    ],
				    "file_info" : {
				      "product_version": "Product version (String)",
				      "original_filename": "Original file name (String)",
				      "file_version": "File Version (String)",
				      "legal_copyright": "Copyright (String)",
				      "company_name": "Company name (String)",
				      "internal_name": "Internal name of the program (String)",
				      "product_name": "Product name (String)",
				      "file_description": "File description (String)"
				    },
				    "export_info" : [
				      {
				        "function_list" : "List of the functions (Array)"
				      }
				    ]
				  },
				  "strings_result" : {
				    "version" : "version of strings output format (String)",
				    "date" : "date time of strings extraction (String)",
				    "strings" : "List of meaningful strings extracted using regular expressions (Array)"
				  }
				}
			"""

			url=urlparse.urljoin(self.baseURL, "staticinfo")
			param={'api_key':self.api_key, 'hash':hashValue}
			
			response=requests.get(url, param)
			return response.json()

		def addinfo(self, hashValue):
			""" File Additional Report
			Get additional information.

			Args:
				hashValue (str) : File Hash (MD5, SHA1, SHA256)

			Returns:
				json: json results

			Return Example:
				{
				  "result_code": "Result Code (Number)",
				  "result_msg": "Result Message (String)",
				  "version": "API page version (String)",
				  "date": "date time of API request (String)",
				  "md5": "MD5 Hash value of the Object (String)",
				  "sha1": "SHA1 hash value of the object (String)",
				  "sha256": "SHA256 Hash value of the object (String)",
				  "filename": "list of names with the same file object (Array),",
				  "distribution_url": "list of urls where files are distributed (Array)"
				}
			"""
			url=urlparse.urljoin(self.baseURL, "addinfo")
			param={'api_key':self.api_key, 'hash':hashValue}
			
			response=requests.get(url, param)
			return response.json()

		def download(self, hashValue):
			""" File Download
			Download file according to requested hashValue.

			Args:
				hashValue (str) : File Hash (MD5, SHA1, SHA256)
				targetPath (str) : target directory or path to save downloaded file
				fileName (str) : file name for saved

			Returns:
				Response object

			Example:
				with open("4020ce0de0cc206f9bc241e5634a02da", "wb") as fd:
					fd.write(mws.file.download("4020ce0de0cc206f9bc241e5634a02da").content)

			"""

			# if self.api_type=="private":
			url=urlparse.urljoin(self.baseURL, "download")
			
			if re.findall(r'^(?:[a-fA-F\d]{64})$', hashValue):
				sha2hash=hashValue
			else:
				# try get sha256 value from hash
				sha2hash=self.mwsinfo(hashValue)['sha256']

			param={'api_key':self.api_key, 'hash':sha2hash}
			
			response=requests.get(url, param)
			return response.content

	class _url:
		def __init__(self, api_key, api_type, baseURL):
			self.api_key=api_key
			self.api_type=api_type
			self.baseURL=urlparse.urljoin(baseURL,"url/")

		def request(self, urlTarget):
			"""URL Analysis Request

			Args:
				urlTarget (str) : URL string for analysis request.

			Returns: 
				json: json results

			Return Example:
				{
				  "result_code": "Result Code (Number)",
				  "result_msg": "Result Message (String)",
				  "version": "API page version (String)",
				  "date": "date time of API request (String)",
				  "url": "requested url for analysis (String)"
				}
			"""


			url=urlparse.urljoin(self.baseURL, "request")
			# given up due to the weird api design.
			# if type(urlTarget) == type(list()):
			# 	url=url.replace("/v3/","/v3/bulk/")
			# 	param={'api_key':self.api_key, 'req_data':urlTarget}
			# else:
			param={'api_key':self.api_key, 'url':urlTarget}

			print param, url
			response=requests.post(url, param)
			return response.json()

		def info(self, urlTarget=None, req_id=None):
			"""URL Report

			Args:
				urlTarget (str) : get report of URL string for analyzed request.
				req_id (str) : request ID from malwares.com for bulk request.

			Returns: 
				json: json results

			Return Example:
				{
				  "result_code": "Result Code (Number)",
				  "result_msg": "Result Message (String)",
				  "version": "API page version (String)",
				  "date": "date time of API request (String)",
				  "url": "URL requested for analysis (String)",
				  "view_count": "URL lookup count (Number)",
				  "smishing": "1 if the URL is categorized as Smishing (Number)",
				  "downloaded_malicious_file": {
				    "total" : "Number of malicious files downloaded from the URL (Number)",
				    "list" : "List of malicious files downloaded from the URL (Array)"
				  },
				  "downloaded_safe_file": {
				      "total" : "Number of normal files downloaded from the URL (Number)",
				      "list" : "List of normal files downloaded from the URL (Array)"
				    },
				  "same_hostname": {
				      "total" : "Number of URLs with the same hostname (Number)",
				      "list" : "List of URLs with the same hostname (Array)"
				  }
				}
			"""
			url=urlparse.urljoin(self.baseURL, "info")
			param={'api_key':self.api_key, 'url':urlTarget}

			response=requests.post(url, param)
			return response.json()

	class _ip:
		def __init__(self, api_key, api_type, baseURL):
			self.api_key=api_key
			self.api_type=api_type
			self.baseURL=urlparse.urljoin(baseURL,"ip/")

		def info(self, ip):
			"""IP Report
		
			Args:
				ip (str): ip address

			Returns:
				json: json results

			Return Example:
				{
				  "result_code": "Result Code (Number)",
				  "result_msg": "Result Message (String)",
				  "version": "API page version (String)",
				  "date": "date time of API request (String)",
				  "ip": "requested IP address for lookup (String)",
				  "view_count": "IP lookup count (Number)",
				  "whois": "IP Whois lookup information (String)",
				  "location": {
				    "cc" : "Country Code (String)",
				    "cname" : "Country Name (String)",
				    "city" : "City Name (String)",
				    "longitude" : "Longitude (String)",
				    "latitude" : "Latitude (String)"
				  },
				  "hostname_history": {
				    "total" : "Number of hostnames that used the IP (Number)",
				    "list" : "List of hostnames that used the IP (Array)"
				  },
				  "detected_url": {
				    "total" : "Number of malicious urls that used the IP (Number)",
				    "list" : "List of malicious urls that used the IP (Array)"
				  },
				  "undetected_url": {
				    "total" : "Number of normal urls that used the IP (Number)",
				    "list" : "List of normal urls that used the IP (Array)"
				  },
				  "detected_downloaded_file": {
				    "total" : "Number of malicious files downloaded from the IP (Number)",
				    "list" : "List of malicious files downloaded from the IP (Array)"
				  },
				  "undetected_downloaded_file": {
				    "total" : "Number of normal files downloaded from the IP (Number)",
				    "list" : "List of normal files downloaded from the IP (Array)"
				  },
				  "detected_communicating_file": {
				    "total" : "Number of malicious files that have communicated to the IP (Number)",
				    "list" : "List of malicious files that have communicated to the IP (Array)"
				  },
				  "undetected_communicating_file": {
				    "total" : "Number of normal files that have communicated to the IP (Number)",
				    "list" : "List of normal files that have communicated to the IP (Array)"
				  }
				}

			"""
			url=urlparse.urljoin(self.baseURL, "info")
			param={'api_key':self.api_key, 'ip':ip}

			response=requests.get(url, param)
			return response.json()

	class _hostname:
		def __init__(self, api_key, api_type, baseURL):
			self.api_key=api_key
			self.api_type=api_type
			self.baseURL=urlparse.urljoin(baseURL,"hostname/")

		def info(self, hostname):
			"""Hostname Report

			Args:
				hostname (str): hostname

			Returns:
				json: json results

			Return Example:
				{
				  "result_code": "Result Code (Number)",
				  "result_msg": "Result Message (String)",
				  "version": "API page version (String)",
				  "date": "date time of API request (String)",
				  "hostname": "hostname of request origin (String)",
				  "view_count": "Hostname lookup count (Number)",
				  "whois": "Hostname Whois 조회 정보 (String)",
				  "location": [{
				    "cc" : "Country Code (String)",
				    "cname" : "Country Name (String)",
				    "city" : "City Name (String)",
				    "longitude" : "Longitude (String)",
				    "latitude" : "Latitude (String)"
				    "iplist" : "list of realated ip (Array)"
				  }],
				  "ip_history": {
				    "total" : "Number of IP address that used the hostname (Number)",
				    "list" : "List of IP address that used the hostname (Array)"
				  },
				  "detected_url": {
				    "total" : "Number of malicious urls that used the hostname (Number)",
				    "list" : "List of malicious urls that used the hostname(Array)"
				  },
				  "undetected_url": {
				    "total" : "Number of normal urls that used the hostname (Number)",
				    "list" : "List of normal urls that used the hostname(Array)"
				  },
				  "detected_downloaded_file": {
				    "total" : "Number of malicious files downloaded from the hostname (Number)",
				    "list" : "List of malicious files downloaded from the hostname (Array)"
				  },
				  "undetected_downloaded_file": {
				    "total" : "Number of normal files downloaded from the hostname (Number)",
				    "list" : "List of normal files downloaded from the hostname (Array)"
				  },
				  "detected_communicating_file": {
				    "total" : "Number of malicious files that have communicated to the hostname (Number)",
				    "list" : "List of malicious files that have communicated to the hostname (Array)"
				  },
				  "undetected_communicating_file": {
				    "total" : "Number of normal files that have communicated to the hostname  (Number)",
				    "list" : "List of normal files that have communicated to the hostname (Array)"
				  }
				}
			"""
			url=urlparse.urljoin(self.baseURL, "info")
			param={'api_key':self.api_key, 'hostname':hostname}

			response=requests.get(url, param)
			return response.json()

	class _tag:
		def __init__(self, api_key, api_type, baseURL):
			self.api_key=api_key
			self.api_type=api_type
			self.baseURL=urlparse.urljoin(baseURL,"tag/")

		def search(self, tag, start=None, end=None, limit=None):
			"""Tag Search
			
			Args:
				tag (str): exe_32bit, etc
				start (datetime object or text): '%Y-%m-%d %H:%M:%S' (optional)
				end (datetime object or text):  '%Y-%m-%d %H:%M:%S' (optional)
				limit (int): number of limit (optional)

			Returns:
				json: json results

			Return Example:
				{
				  "list": [
				    {
				      "sha256": "2F215F7D43201330D3CD11A09E86218B9E0EAE4C1E224932159A9BF3D6381D94",
				      "tags": [
				        "exe_32bit",
				        "interested_strings_url",
				        "overlay",
				        "peexe"
				      ]
				    },
				    {
				      "sha256": "AB9C862351B2E8B548829B8FFE29574C66DC4B8E2D3A895A0CB01E5A7803B6DE",
				      "tags": [
				        "exe_32bit",
				        "interested_strings_ip",
				        "interested_strings_path",
				        "interested_strings_url",
				        "overlay",
				        "packing",
				        "peexe",
				        "upx"
				      ]
				    },
				    {
				      "sha256": "F14ACCEEEDD10ACA13A0B019DD1746161B0A31F69F101FBD46970558E6A036C6",
				      "tags": [
				        "exe_32bit",
				        "interested_strings_ip",
				        "interested_strings_url",
				        "overlay",
				        "peexe"
				      ]
				    },
				    {
				      "sha256": "378ED05D0C6DB1C05E51BDD6A2D44D559DE3E3468679171CED5B99432935ADD6",
				      "tags": [
				        "exe_32bit",
				        "interested_strings_ip",
				        "interested_strings_path",
				        "interested_strings_url",
				        "overlay",
				        "peexe"
				      ]
				    },
				    {
				      "sha256": "1AABCA312387DD0F316BFDFE84186B9B597279ACC229873D78A23B221E336EEE",
				      "tags": [
				        "exe_32bit",
				        "nxdomain",
				        "overlay",
				        "peexe"
				      ]
				    },
				    {
				      "sha256": "D19EC85D0093E28D35E969E422A245B35126432728E78ABB4620909F53CFBBE8",
				      "tags": [
				        "exe_32bit",
				        "interested_strings_path",
				        "interested_strings_url",
				        "peexe"
				      ]
				    },
				    {
				      "sha256": "BC8B9D66633E4A4ED834BC022497FB31273F2CCD13386A870A55081A521EA0F8",
				      "tags": [
				        "aspack",
				        "exe_32bit",
				        "interested_strings_path",
				        "interested_strings_url",
				        "packing",
				        "peexe"
				      ]
				    },
				    {
				      "sha256": "BD840A2441A01EAAD4A5C39B1D8DC49F3C829C5FAB0652DE9ECB20301427B3B1",
				      "tags": [
				        "bobsoft",
				        "exe_32bit",
				        "interested_strings_url",
				        "packing",
				        "peexe",
				        "upx"
				      ]
				    },
				    {
				      "sha256": "2CBCA30AEF7DE44976035ACA3F1F93EC7D3DF04CC343CB299293F55AE3F63B70",
				      "tags": [
				        "exe_32bit",
				        "interested_strings_ip",
				        "peexe"
				      ]
				    },
				    {
				      "sha256": "6502D8EAEF87E099B977831033478CBE04C76AE091CB23AA538630EDE5DAC428",
				      "tags": [
				        "exe_32bit",
				        "interested_strings_path",
				        "interested_strings_url",
				        "overlay",
				        "peexe"
				      ]
				    }
				  ],
				  "result_code": 1,
				  "result_msg": "Data exists"
				}
			"""
			url=urlparse.urljoin(self.baseURL, "search")
			param={'api_key':self.api_key, 'tag':tag}
			if start is not None:
				try:
					param['start']=start.strftime('%Y-%m-%d %H:%M:%S')
				except:
					param['start']=parser.parse(start).strftime('%Y-%m-%d %H:%M:%S')
			if end is not None:
				try:
					param['end']=end.strftime('%Y-%m-%d %H:%M:%S')
				except:
					param['end']=parser.parse(end).strftime('%Y-%m-%d %H:%M:%S')
			if limit is not None:
				try:
					param['limit']=str(limit)
				except:
					pass

			response=requests.get(url, param)
			return response.json()
