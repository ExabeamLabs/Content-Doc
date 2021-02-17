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
    """({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d.\d\d\d)""",
    """UserName=({user}[^,]+)""",
    """Device\sIP\sAddress=({src_ip}\d+.\d+.\d+.\d+)""",
    """NetworkDeviceName=({src_host}[^,]+)""",
    """Calling-Station-ID=({dest_host}[^,]+)""",
    """NAS-IP-Address=({dest_ip}\d+.\d+.\d+.\d+)""",
    """NAS-Port=({dest_port}[^,]+)""",
    """Acct-Session-Time=({session_duration}[^,]+)""",
    """Acct-Terminate-Cause=({reason}[^,]+)""",

  ]
}
```