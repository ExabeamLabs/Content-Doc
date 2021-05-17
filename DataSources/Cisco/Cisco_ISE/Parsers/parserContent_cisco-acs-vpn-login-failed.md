#### Parser Content
```Java
{
Name = cisco-acs-vpn-login-failed
  Vendor = Cisco
  Product = Cisco ISE
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """CSCOacs_Failed_Attempts""", """Failed-Attempt: Authentication failed""", """NAS-Port-Type=Virtual""" ]
  Fields = [
    """\d{1,100}\s{1,100}({time}\d\d\d\d\-\d\d\-\d\d \d{1,100}:\d{1,100}:\d{1,100})""",
    """CSCOacs_Failed_Attempts\s{1,100}(\d{1,100}\s{1,100}){3}\s{1,100}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[^\s]{1,2000})""",
    """({dest_host}[^\s]{1,2000})\s{1,100}CSCOacs_Failed_Attempts""",
    """,\s{0,100}User-Name=(({domain}[^\s\\\/]{1,2000})(\/+|\\+))?(?:(\w{2}\-){5}\w{2}|({user}[^,]{1,2000}))""",
    """Tunnel-Client-Endpoint=\(.+\)\s({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """Framed-IP-Address=({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),"""
    """,\s{0,100}Device IP Address=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\WFailed-Attempt:\s{0,100}({failure_reason}[^,]{1,2000})""",
    """\s{0,100}DestinationIPAddress=({auth_server}[a-fA-F\d.:]{1,2000})""",
    """\s{0,100}Device Port=({dest_port}\d{1,100})""",
    """AcsSessionID=({session_id}[^,]{1,2000})""",
    """({event_name}CSCOacs_Failed_Attempts)""",
    """device-platform=({os}[^,\s]{1,2000})""",
    """device-platform-version=({os_version}[^,\s]{1,2000})""",
    """Group-Name=({realm}[^,\s]{1,2000})""",
    """\s{0,100}ConfigVersionId=({badg_id}\d{1,100})""",
    """({event_code}5400)""",
  ]
  DupFields = ["user->account"]
}
```