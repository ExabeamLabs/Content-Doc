#### Parser Content
```Java
{
Name = nnt-ct-app-login
  Vendor = NNT
  Product = NNT ChangeTracker
  Lms = Splunk
  DataType = "app-login"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """|NNT|ChangeTracker Gen 7|""", """|402|Audit User Admin: Successful Logon|""" ]
  Fields = [
    """rt=({time}\w+\s\d\d\s\d\d\d\d\s\d\d:\d\d:\d\d)""",
    """src=({host}[\w\-.]+)\s""",
    """CEF:([^|]*\|){4}({event_code}\d{1,100})""",
    """CEF:([^|]*\|){5}({event_name}[^|]+)""",
    """msg=({additional_info}[^=]+?)\s{0,100}(\w+=|$)""",
    """({app}NNT\|ChangeTracker Gen 7)""",
    """suser=({user}\S+)\s\(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """({auth_type}AD)"""
  ]
}
```