#### Parser Content
```Java
{
Name = syslog-xceedium-login
  Vendor = Xceedium
  Product = Xceedium
  Lms = Direct
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [  """Message 18019:""", """logged in successfully""" ]
  Fields = [
    """exabeam_host=([^=]+?@\s*)?({host}[^\s]+)""",
    """"+({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)"+\s*,""",
    ""","(|[- ]+|({src_ip}\S+?))",((\s*"([^"]|"")+")\s*,|[^",]+?,|\s*,){9}\s*"Message 18019:""",
    """"Message 18019:\s*User\s+({user}.+?)\s+logged in successfully""",
  ]
  DupFields = ["host->dest_host"]
}
```