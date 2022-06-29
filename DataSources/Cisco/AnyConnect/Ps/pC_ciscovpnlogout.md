#### Parser Content
```Java
{
Name = cisco-vpn-logout
  Vendor = Cisco
  Product = AnyConnect
  Lms = Splunk
  DataType = "vpn-end"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [ """cisco-av-pair=mdm-tlv=ac-user-agent=AnyConnect""", """Acct-Status-Type=Stop""" ]
  Fields = [
    """\d\d:\d\d:\d\d\s({host}[^\s]{1,2000})""",
    """({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d.\d\d\d)""",
    """UserName =(({user_email}[^@,]{1,2000}@[^,]{1,2000})|({user}[^,]{1,2000}))""",
    """Device\sIP\sAddress=({src_ip}\d{1,100}.\d{1,100}.\d{1,100}.\d{1,100})""",
    """NetworkDeviceName =({src_host}[^,]{1,2000})""",
    """NAS-IP-Address=({dest_ip}\d{1,100}.\d{1,100}.\d{1,100}.\d{1,100})""",
    """Calling-Station-ID=(({dest_ip}(\d{1,3}\.){3}\d{1,3})|({dest_host}[^,]{1,2000}))""",
    """Acct-Session-Time=({session_duration}[^,]{1,2000})""",
    """Acct-Terminate-Cause=({reason}[^,]{1,2000})"""
  ]


}
```