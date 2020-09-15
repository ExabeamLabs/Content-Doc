#### Parser Content
```Java
{
Name = leef-pan-remote-logon
  Vendor = Palo Alto Networks
  Product = NGFW
  Lms = Direct
  DataType = "remote-logon"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ "|Palo Alto Networks|" , "subtype=general", "logged in via" ]
  Fields = [
    """exabeam_host=(.+?@\s*)?({host}[^\s]+)""",
    """ReceiveTime=({time}\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d)""",
    """User ({user}[^\s]+) logged in via\s+\w+\s+from\s*(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^,]+))"""
    """msg=".+?using\s*({auth_method}[^"]+)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```