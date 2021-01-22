#### Parser Content
```Java
{
Name = cisco-acs-vpn-login-failed
  Vendor = Cisco
  Product = Cisco ISE
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "CSCOacs_Failed_Attempts", "Failed-Attempt: Authentication failed", "NAS-Port-Type=Virtual" ]
  Fields = [
    """\d+\s+({time}\d\d\d\d\-\d\d\-\d\d \d+:\d+:\d+)""",
    """CSCOacs_Failed_Attempts\s+(\d+\s+){3}\s+({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[^\s]+)""",
    """({dest_host}[^\s]+)\s+CSCOacs_Failed_Attempts""",
    """,\s*User-Name=(({domain}[^\s\\\/]+)(\/+|\\+))?(?:(\w{2}\-){5}\w{2}|({user}[^,]+))""",
    """Tunnel-Client-Endpoint=\(.+\)\s({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """Framed-IP-Address=({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),"""
    """,\s*Device IP Address=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\:\d\d\s({dest_host}.+?)\sCSCOacs""",
    """\WFailed-Attempt:\s*({failure_reason}[^,]+)"""
  ]
}
```