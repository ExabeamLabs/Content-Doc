#### Parser Content
```Java
{
Name = cisco-acs-vpn-logout
  Vendor = Cisco
  Product = Cisco ISE
  Lms = Direct
  DataType = "vpn-end"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "CSCOacs_RADIUS_Accounting", "RADIUS Accounting stop request,", "Acct-Status-Type=Stop", "NAS-Port-Type=Virtual" ]
  Fields = [
    """\d+\s+({time}\d\d\d\d\-\d\d\-\d\d \d+:\d+:\d+)""",
    """CSCOacs_RADIUS_Accounting\s+(\d+\s+){3}\s+({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[^\s]+)""",
    """({host}[^\s]+)\s+CSCOacs_RADIUS_Accounting""",
    """,\s*User-Name=(({domain}[^\s\\\/]+)[\\\/]+)?(?:(\w{2}\-){5}\w{2}|({user}[^,]+))""",
    """Tunnel-Client-Endpoint=\(.+?\)\s({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """Framed-IP-Address=({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),"""
    """\:\d\d\s+({dest_host}.+?)\sCSCOacs""",
    """,\s*Device IP Address=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """Acct-Output-Octets=({bytes_recieved}\d+),""",
    """Acct-Input-Octets=({bytes_sent}\d+),""",
    """Acct-Session-Time=({session_duration}\d+),""",
    """Acct-Terminate-Cause=({additional_info}.*?),\sNAS-Port""",
  ]
}
```