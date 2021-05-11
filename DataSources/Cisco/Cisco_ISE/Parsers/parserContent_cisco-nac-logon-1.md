#### Parser Content
```Java
{
Name = cisco-nac-logon-1
  Vendor = Cisco
  Product = Cisco ISE
  Lms = Direct
  DataType = "nac-logon"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS Z"
  Conditions = [ """Device-Administration: Command Authorization succeeded""", """CSCOacs_Passed_Authentications""" ]
  Fields = [
    """({host}[\w.\-]+)\s{1,100}CSCOacs_Passed_Authentications(\s{1,100}\S+){3}\s{1,100}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d{1,100} (\+|\-)\d\d:\d\d)""",
    """Device-Administration:\s{0,100}({event_name}[^,]+)""",
    """, Device IP Address=({auth_server}[^,]+)""",
    """, DestinationIPAddress=({dest_ip}[a-fA-F\d.:]+)""",
    """, DestinationPort=({dest_port}\d{1,100})""",
    """, UserName=({user}[^,]+)""",
    """, Protocol=({protocol}[^,]+)""",
    """, Remote-Address=({src_ip}[^,]+)""",
    """, AuthenticationMethod=({auth_type}[^,]+)"""
  ]
}
```