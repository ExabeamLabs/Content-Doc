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
    """src=({host}[\w\-.]{1,2000})\s""",
    """CEF:([^|]{0,2000}\|){4}({event_code}\d{1,100})""",
    """CEF:([^|]{0,2000}\|){5}({event_name}[^|]{1,2000})""",
    """msg=({additional_info}[^=]{1,2000}?)\s{0,100}(\w+=|$)""",
    """({app}NNT\|ChangeTracker Gen 7)""",
    """suser=({user}\S+)\s\(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """({auth_type}AD)"""
  ]
}
```