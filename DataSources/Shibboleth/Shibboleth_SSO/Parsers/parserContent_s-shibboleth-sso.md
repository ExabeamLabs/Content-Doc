#### Parser Content
```Java
{
Name = s-shibboleth-sso
    Vendor = Shibboleth
  Product = Shibboleth SSO
    Lms = Splunk
    DataType = "app-login"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """[Shibboleth-Audit""" ]
    Fields = [
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """({src_ip}[a-fA-F\d.:]+)\s{0,100}$""",
      """({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s{1,100}\- \[({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """exabeam_host=({host}[^\s]+)""",
      """\w+\s{1,100}\d{1,100}\s{1,100}\d\d:\d\d:\d\d\s{1,100}({host}[\w\-.]+)\s{1,100}\[""",
      """(?:[^\|]*\|){8}({user}[^\|]+)?""",
      """(?:[^\|]*\|){3}({app}[^\|]+)?""",
    ]
  }
```