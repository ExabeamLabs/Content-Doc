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
    """({host}[\w.\-]+)\s+CSCOacs_Passed_Authentications(\s+\S+){3}\s+({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d+ (\+|\-)\d\d:\d\d)""",
    """Device-Administration:\s*({event_name}[^,]+)""",
    """, Device IP Address=({auth_server}[^,]+)""",
    """, DestinationIPAddress=({dest_ip}[a-fA-F\d.:]+)""",
    """, DestinationPort=({dest_port}\d+)""",
    """, UserName=({user}[^,]+)""",
    """, Protocol=({protocol}[^,]+)""",
    """, Remote-Address=({src_ip}[^,]+)""",
    """, AuthenticationMethod=({auth_type}[^,]+)"""
  ]
}
```