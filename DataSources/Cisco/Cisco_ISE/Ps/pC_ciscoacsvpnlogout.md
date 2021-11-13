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
    """\d{1,100}\s{1,100}({time}\d\d\d\d\-\d\d\-\d\d \d{1,100}:\d{1,100}:\d{1,100})""",
    """CSCOacs_RADIUS_Accounting\s{1,100}(\d{1,100}\s{1,100}){3}\s{1,100}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[^\s]{1,2000})""",
    """({host}[^\s]{1,2000})\s{1,100}CSCOacs_RADIUS_Accounting""",
    """,\s{0,100}User-Name =(({domain}[^\s\\\/]{1,2000})[\\\/]{1,2000})?(?:(\w{2}\-){5}\w{2}|({user}[^,]{1,2000}))""",
    """Tunnel-Client-Endpoint=\(.+?\)\s({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """Framed-IP-Address=({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),"""
    """\:\d\d\s{1,100}({dest_host}.+?)\sCSCOacs""",
    """,\s{0,100}Device IP Address=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """Acct-Output-Octets=({bytes_recieved}\d{1,100}),""",
    """Acct-Input-Octets=({bytes_sent}\d{1,100}),""",
    """Acct-Session-Time=({session_duration}\d{1,100}),""",
    """Acct-Terminate-Cause=({additional_info}.*?),\sNAS-Port""",
  ]


}
```