#### Parser Content
```Java
{
Name = cisco-acs-nac-logon
  Vendor = Cisco
  Product = Cisco ISE
  Lms = Direct
  DataType = "nac-logon"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "CSCOacs_RADIUS_Accounting", "RADIUS Accounting start request,", "Acct-Status-Type=Start" ]
  Fields = [
    """\d{1,100}\s{1,100}({time}\d\d\d\d\-\d\d\-\d\d \d{1,100}:\d{1,100}:\d{1,100})""",
    """CSCOacs_RADIUS_Accounting\s{1,100}(\d{1,100}\s{1,100}){3}\s{1,100}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[^\s]+)""",
    """({host}[^\s]+)\s{1,100}CSCOacs_RADIUS_Accounting""",
    """,\s{0,100}User-Name=(({domain}[^\s\\\/]+)(\/+|\\+))?(?:(\w{2}\-){5}\w{2}|({user}[^,]+))""",
    """,\s{0,100}Calling-Station-ID=({dest_host}[^,]+)""",
    """,\s{0,100}AD-Host-Resolved-Identities=({dest_host}[^@,]+)""",
    """,\s{0,100}Device IP Address=({auth_server}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """,\s{0,100}Device IP Address=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """,\s{0,100}Framed-IP-Address=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
  ]
}
```