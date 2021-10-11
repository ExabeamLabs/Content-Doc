#### Parser Content
```Java
{
Name = syslog-xceedium-failed-login
  Vendor = Xceedium
  Product = Xceedium
  Lms = Direct
  DataType = "failed-app-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Message 18002:""", """Bad User ID""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[^\s]{1,2000})""",
    """"{1,20}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)"{1,20}\s{0,100},""",
    ""","(|[- ]{1,2000}|({src_ip}\S+?))",((\s{0,100}"([^"]|"")+")\s{0,100},|[^",]{1,2000}?,|\s{0,100},){9}\s{0,100}"Message 18002:""",
    """Message 18002:\s{0,100}Bad User ID\s{0,100}\(\s{0,100}({user}.+?)\s{0,100}\)""",
    """({result_code}18002)""",
  ]
  DupFields = ["host->dest_host"]
}
```