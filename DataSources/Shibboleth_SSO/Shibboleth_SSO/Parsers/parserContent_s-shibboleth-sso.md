#### Parser Content
```Java
{
Name = s-shibboleth-sso
    Vendor = Shibboleth SSO
  Product = Shibboleth SSO
    Lms = Splunk
    DataType = "app-login"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """[Shibboleth-Audit""" ]
    Fields = [
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """({src_ip}[a-fA-F\d.:]+)\s*$""",
      """({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+\- \[({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """exabeam_host=({host}[^\s]+)""",
      """\w+\s+\d+\s+\d\d:\d\d:\d\d\s+({host}[\w\-.]+)\s+\[""",
      """(?:[^\|]*\|){8}({user}[^\|]+)?""",
      """(?:[^\|]*\|){3}({app}[^\|]+)?""",
    ]
  }
```