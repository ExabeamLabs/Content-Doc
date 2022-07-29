#### Parser Content
```Java
{
Name = cisco-ucs-authentication-failed
  Vendor = Cisco
  Product = Unified Computing System
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "yyyy MMM dd HH:mm:ss zzz"
  Conditions = [ """Authentication failed for User:""", """%USER-2-SYSTEM_MSG:""" ]
  Fields = [
    """\s({host}[a-fA_F0-9.:]{1,2000})\s{1,100}:""",
    """({time}\d{4}\s\w{3}\s\d{2}\s(\d{2}:){2}\d{2}\s\S{1,2000}?):""",
    """Authentication failed for User:\s{1,100}({user}\S{1,2000})\s""",
    """({event_name}Authentication failed for User):"""
  ]
   DupFields = [ "host->dest_ip" ]


}
```