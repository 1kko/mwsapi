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
				  "result_code": "결과 코드 (Number)",
				  "result_msg": "결과 메시지 (String)",
				  "version": "API 페이지 버전 (String)",
				  "date": "API 요청 시간 (String)",
				  "md5": "파일의 MD5 해시 값 (String)",
				  "sha1": "파일의 SHA1 해시 값 (String)",
				  "sha256": "파일의 SHA256 해시 값 (String)"
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
				  "date": "API Request Time (String)",
				  "md5": "MD5 Hash value of the file (String)",
				  "sha1": "SHA1 Hash value of the file (String)",
				  "sha256": "SHA256 Hash value of the file (String)",
				  "view_count": "Search Count of the file (Number)",
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
			  "result_code": "결과 코드 (Number)",
			  "result_msg": "결과 메시지 (String)",
			  "version": "API 페이지 버전 (String)",
			  "date": "API 요청 시간 (String)",
			  "md5": "파일의 MD5 해시 값 (String)",
			  "sha1": "파일의 SHA1 해시 값 (String)",
			  "sha256": "파일의 SHA256 해시 값 (String)",
			  "view_count": "파일의 조회 카운트 (Number)",
			  "black_white": "블랙/화이트 리스트 여부. 1은 블랙리스트, 2는 화이트리스트 (Number)",
			  "filetype": "파일의 포맷 (String)",
			  "filesize": "파일의 크기 (Number)",
			  "first_seen": "파일의 최초 수집 날짜(String)",
			  "ai_score": "MAX AI에 의하여 생성된 결과 값 (Number)",
			  "taglist": "파일의 태그 명 목록 (Array)",
			  "tag_name_etc" : "파일의 프로파일링 태그 목록 (Array)", 
			  "imphash" : "PE 타입 파일의 Import Table 기반 해시 값 (String)",
			  "ssdeep" : "파일의 ssdeep 기반 해시 값 (String)",
			  "behavior": {
			    "행위분석 환경": {
			      "date": "행위분석 날짜 (String)",
			      "detection": "악성탐지 된 행위 목록 (Array)",
			      "security_level": "행위분석 위험도. 1은 악성, 2은 위험, 3은 정상 (Number)"
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
				  "result_code": "결과 코드 (Number)",
				  "result_msg": "결과 메시지 (String)",
				  "version": "API 페이지 버전 (String)",
				  "date": "API 요청 시간 (String)",
				  "md5": "파일의 MD5 해시 값 (String)",
				  "sha1": "파일의 SHA1 해시 값 (String)",
				  "sha256": "파일의 SHA256 해시 값 (String)",
				  "format_type" :  "정적분석 결과 형식 타입 (String)",
				  "peinfo" : {
				    "version": "peinfo 결과 형식 버전 (String)",
				    "date": "peinfo 추출 날짜 (String)",
				    "section_info" : [
				      {
				        "raw_data_hash" : "섹션의 데이터 SHA256 (String)",
				        "raw_data_offset" : "섹션의 파일 내 오프셋 (String)",
				        "section_name" : "섹션 이름 (String)"
				      }
				    ],
				    "pe_info" : [
				      {
				        "subsystem" : " 동작 시스템 (String)",
				        "is_windows_gui" : "윈도우 GUI 타입 (String)",
				        "image_base" : "메모리에 로드되는 시작 주소 (String)",
				        "characteristics" : "파일의 속성 정보 (String)",
				        "pe_file_type" : "PE 타입 (String)",
				        "stored_checksum" : "파일의 체크섬 정보 (String)",
				        "file_alignment" : "파일 상태에서 섹션 크기 단위 (String)",
				        "entry_point" : "프로그램의 시작 주소 (String)",
				        "is_console" : "콘솔 프로그램 타입 (String)",
				        "section_alignment" : "가상 메모리로 로드되는 섹션의 크기 단위 (String)"
				      }
				    ],
				    "signcheck" : {
				      "signing_date" : "서명일 (String)",
				      "signers_details" : "코드 서명 인증서 리스트 (Array)",
				      "verified" : "인증서 서명 검증 결과 (String)",
				      "counter_signers_details" : "타임 스탬프 인증서 리스트 (Array)"
				    },
				    "import_info" : [
				      {
				        "dll_name" : "Import Dll 이름 (String)",
				        "function_list" : "사용하는 함수 리스트 (Array)"
				      }
				    ],
				    "file_info" : {
				      "product_version": "제품 버전 (String)",
				      "original_filename": "프로그램의 원본 이름 (String)",
				      "file_version": "파일 버전 (String)",
				      "legal_copyright": "상표 정보 (String)",
				      "company_name": "회사 이름 (String)",
				      "internal_name": "프로그램 내부 이름 (String)",
				      "product_name": "제품 이름 (String)",
				      "file_description": "파일 설명 (String)"
				    },
				    "export_info" : [
				      {
				        "function_list" : "함수 리스트 (Array)"
				      }
				    ]
				  },
				  "strings_result" : {
				    "version" : "strings 결과 형식 버전 (String)",
				    "date" : "strings 추출 날짜 (String)",
				    "strings" : "정규 표현식을 이용해 추출해 낸 의미있는 strings 목록 (Array)"
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
				  "result_code": "결과 코드 (Number)",
				  "result_msg": "결과 메시지 (String)",
				  "version": "API 페이지 버전 (String)",
				  "date": "API 요청 시간 (String)",
				  "md5": "파일의 MD5 해시 값 (String)",
				  "sha1": "파일의 SHA1 해시 값 (String)",
				  "sha256": "파일의 SHA256 해시 값 (String)",
				  "filename": "파일이 업로드 된 파일명 목록 (Array),",
				  "distribution_url": " 파일의 배포지 URL 목록 (Array)"
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
				  "result_code": "결과 코드 (Number)",
				  "result_msg": "결과 메시지 (String)",
				  "version": "API 페이지 버전 (String)",
				  "date": "API 요청 시간 (String)",
				  "url": "분석 요청한 URL (String)"
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
				  "result_code": "결과 코드 (Number)",
				  "result_msg": "결과 메시지 (String)",
				  "version": "API 페이지 버전 (String)",
				  "date": "API 요청 시간 (String)",
				  "url": "분석 요청한 URL (String)",
				  "view_count": "URL 조회 카운트 (Number)",
				  "smishing": "스미싱 URL 여부, 1이면 스미싱 URL (Number)",
				  "downloaded_malicious_file": {
				    "total" : "URL에서 다운로드 된 악성 파일 개수 (Number)",
				    "list" : "URL에서 다운로드 된 악성 파일 목록 (Array)"
				  },
				  "downloaded_safe_file": {
				      "total" : "URL에서 다운로드 된 정상 파일 개수 (Number)",
				      "list" : "URL에서 다운로드 된 정상 파일 목록 (Array)"
				    },
				  "same_hostname": {
				      "total" : "동일한 호스트 명을 사용하는 URL 개수 (Number)",
				      "list" : "동일한 호스트 명을 사용하는 URL 목록 (Array)"
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
				  "result_code": "결과 코드 (Number)",
				  "result_msg": "결과 메시지 (String)",
				  "version": "API 페이지 버전 (String)",
				  "date": "API 요청 시간 (String)",
				  "ip": "정보 확인을 요청한 IP (String)",
				  "view_count": "IP 조회 카운트 (Number)",
				  "whois": "IP Whois 조회 정보 (String)",
				  "location": {
				    "cc" : "국가 코드 (String)",
				    "cname" : "국가 명 (String)",
				    "city" : "도시 명 (String)",
				    "longitude" : "경도 (String)",
				    "latitude" : "위도 (String)"
				  },
				  "hostname_history": {
				    "total" : "해당 IP를 사용했던 호스트 명 개수 (Number)",
				    "list" : "해당 IP를 사용했던 호스트 명 목록 (Array)"
				  },
				  "detected_url": {
				    "total" : "해당 IP를 사용했던 악성 URL 개수 (Number)",
				    "list" : "해당 IP를 사용했던 악성 URL 목록 (Array)"
				  },
				  "undetected_url": {
				    "total" : "해당 IP를 사용했던 정상 URL 개수 (Number)",
				    "list" : "해당 IP를 사용했던 정상 URL 목록 (Array)"
				  },
				  "detected_downloaded_file": {
				    "total" : "해당 IP에서 다운로드 된 악성 파일 개수 (Number)",
				    "list" : "해당 IP에서 다운로드 된 악성 파일 목록 (Array)"
				  },
				  "undetected_downloaded_file": {
				    "total" : "해당 IP에서 다운로드 된 정상 파일 개수 (Number)",
				    "list" : "해당 IP에서 다운로드 된 정상 파일 목록 (Array)"
				  },
				  "detected_communicating_file": {
				    "total" : "해당 IP와 통신한 악성 파일 개수 (Number)",
				    "list" : "해당 IP와 통신한 악성 파일 목록 (Array)"
				  },
				  "undetected_communicating_file": {
				    "total" : "해당 IP와 통신한 정상 파일 개수 (Number)",
				    "list" : "해당 IP와 통신한 정상 파일 목록 (Array)"
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
				  "result_code": "결과 코드 (Number)",
				  "result_msg": "결과 메시지 (String)",
				  "version": "API 페이지 버전 (String)",
				  "date": "API 요청 시간 (String)",
				  "hostname": "정보 확인을 요청한 Hostname (String)",
				  "view_count": "Hostname 조회 카운트 (Number)",
				  "whois": "Hostname Whois 조회 정보 (String)",
				  "location": [{
				    "cc" : "국가 코드 (String)",
				    "cname" : "국가 명 (String)",
				    "city" : "도시 명 (String)",
				    "longitude" : "경도 (String)",
				    "latitude" : "위도 (String)",
				    "iplist" : "해당되는 IP 리스트 (Array)"
				  }],
				  "ip_history": {
				    "total" : "해당 Hostname이 사용했던 IP 개수 (Number)",
				    "list" : "해당 Hostname이 사용했던 IP 목록 (Array)"
				  },
				  "detected_url": {
				    "total" : "해당 Hostname이 사용했던 악성 URL 개수 (Number)",
				    "list" : "해당 Hostname이 사용했던 악성 URL 목록 (Array)"
				  },
				  "undetected_url": {
				    "total" : "해당 Hostname이 사용했던 정상 URL 개수 (Number)",
				    "list" : "해당 Hostname이 사용했던 정상 URL 목록 (Array)"
				  },
				  "detected_downloaded_file": {
				    "total" : "해당 Hostname에서 다운로드 된 악성 파일 개수 (Number)",
				    "list" : "해당 Hostname에서 다운로드 된 악성 파일 목록 (Array)"
				  },
				  "undetected_downloaded_file": {
				    "total" : "해당 Hostname에서 다운로드 된 정상 파일 개수 (Number)",
				    "list" : "해당 Hostname에서 다운로드 된 정상 파일 목록 (Array)"
				  },
				  "detected_communicating_file": {
				    "total" : "해당 Hostname에서 통신한 악성 파일 개수 (Number)",
				    "list" : "해당 Hostname에서 통신한 악성 파일 목록 (Array)"
				  },
				  "undetected_communicating_file": {
				    "total" : "해당 Hostname에서 통신한 정상 파일 개수 (Number)",
				    "list" : "해당 Hostname에서 통신한 정상 파일 목록 (Array)"
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
