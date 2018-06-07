# mwsapi
Python wrapper for malwares.com API

_Unofficial_ Python Wrapper for malwares.com API (version 3).

Complete API documentation: https://www.malwares.com/about/api


## Requirements

  * Python 2.7 or higher
  * requires: `requests`, `dateutil`, `urllib3`
  * malwares.com API Key.


## Quick Start

```
from mwsapi import v3

# Initialize class, enter API Key and API Type
mws=v3(api_key="YOUR API KEY", api_type="public")

# Get File Analysis Report
print mws.file.mwsinfo("4020ce0de0cc206f9bc241e5634a02da")
```


## Installation

  ### Install `requests`
  ```
  pip install requests
  ```
  ### Install `dateutil`
  ```
  pip install python-dateutil
  ```
  ### Install `urllib3`
  ```
  pip install urllib3
  ```

## Available Methods

  ### file.upload(*filepath*)
  ```
  mws.file.upload("C:\Windows\explorer.exe")
  ```

  ### file.download(*hash*)
  File download supports _both_ sha2hash and md5hash (auto-detection).
  Given md5hash, internally looks up sha2hash value using `file.mwsinfo`, then tries to download with sha2hash acquired.

  ```
  mws.file.download("4020ce0de0cc206f9bc241e5634a02da")
  mws.file.download("94EAC5559220793377C3F3B791AA81D853DEEE34D21467D70799A32EB8D4BD51")
  ```

  ### file.mwsinfo(*hash*)
  File summary report of given hash.
  Supports md5, sha1, sha256.
  ```
  mws.file.mwsinfo("4020ce0de0cc206f9bc241e5634a02da")
  ```

  ### file.behaviorinfo(*hash*)
  Returns behavior report for given hash.
  Supports md5, sha1, sha256.
  ```
  mws.file.behaviorinfo("4020ce0de0cc206f9bc241e5634a02da")
  ```

  ### file.staticinfo(`hash`)
  Reports static analysis of given hash.
  Supports md5, sha1, sha256.
  ```
  mws.file.staticinfo("4020ce0de0cc206f9bc241e5634a02da")
  ```

  ### file.addinfo(*hash*)
  Returns additional information of given hahs.
  Supports md5, sha1, sha256.
  ```
  mws.file.addinfo("4020ce0de0cc206f9bc241e5634a02da")
  ```

  ### url.request(*url*)
  Requests url for analysis.
  ```
  mws.url.request("https://www.malwares.com")
  ```

  ### url.info(*url*)
  Get url analysis report.
  ```
  mws.url.info("https://www.malwares.com")
  ```

  ### ip.info(*ip_address*)
  Get ip analysis report.
  ```
  mws.ip.info("8.8.8.8")
  ```

  ### hostname.info(*domain_name*)
  Get public domain analysis report.
  ```
  mws.hostname.info("google.com")
  ```

  ### tag.search(*tag*)
  Search objects according to given tag.
  ```
  mws.tag.search("ransomware")
  ```


## TODO (not yet implemented)
[ ] Return Code parsing
[ ] Full English documentation for methods
[ ] bulk API support (maybe)
