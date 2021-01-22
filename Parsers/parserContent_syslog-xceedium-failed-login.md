#### Parser Content
```Java
{
Name = syslog-xceedium-failed-login
  Vendor = Xceedium
  Lms = Direct
  DataType = "failed-app-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Message 18002:""", """Bad User ID""" ]
  Fields = [
    """exabeam_host=([^=]+?@\s*)?({host}[^\s]+)""",
    """"+({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)"+\s*,""",
    ""","(|[- ]+|({src_ip}\S+?))",((\s*"([^"]|"")+")\s*,|[^",]+?,|\s*,){9}\s*"Message 18002:""",
    """Message 18002:\s*Bad User ID\s*\(\s*({user}.+?)\s*\)""",
    """({result_code}18002)""",
  ]
  DupFields = ["host->dest_host"]
}
```