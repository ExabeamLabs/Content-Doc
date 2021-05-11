#### Parser Content
```Java
{
Name = f5-vpn-user
  Vendor = F5
  Product = F5 BIG-IP
  Lms = Splunk
  DataType = "vpn-user"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """01490""", """:5:""", """Username """ ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\s({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)\s""",
    """\d\d:\d\d\s{1,100}({host}[^\s]+)\s([^\s]+\s)?[^\s]+\[\d{1,100}\]""",
    """hostname="({host}[\w\-.]+)""",
    """"host":\{"name":"({host}[^"]+)""",
    """\s01490\d{1,100}:5:.*?({session_id}[^\s:]+): (Username|Retry)""",
    """\sUsername\s{1,100}'(?:[^\\]+\\+)?({user}[^'\\]+)'"""
  ]
}
```