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
    """({host}[\w.\-]{1,2000})\s{1,100}CSCOacs_Passed_Authentications(\s{1,100}\S+){3}\s{1,100}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d{1,100} (\+|\-)\d\d:\d\d)""",
    """Device-Administration:\s{0,100}({event_name}[^,]{1,2000})""",
    """, Device IP Address=({auth_server}[^,]{1,2000})""",
    """, DestinationIPAddress=({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """, DestinationPort=({dest_port}\d{1,100})""",
    """, UserName=({user}[^,]{1,2000})""",
    """, Protocol=({protocol}[^,]{1,2000})""",
    """, Remote-Address=({src_ip}[^,]{1,2000})""",
    """, AuthenticationMethod=({auth_type}[^,]{1,2000})"""
  ]
}
```