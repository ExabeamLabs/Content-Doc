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
    """exabeam_host=(.+?@\s{0,100})?({host}[^\s]{1,2000})""",
    """ReceiveTime=({time}\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d)""",
    """User ({user}[^\s]{1,2000}) logged in via\s{1,100}\w+\s{1,100}from\s{0,100}(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^,]{1,2000}))"""
    """msg=".+?using\s{0,100}({auth_method}[^"]{1,2000})"""
  ]
  DupFields = [ "host->dest_host" ]
}
```