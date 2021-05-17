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
      """({src_ip}[a-fA-F\d.:]{1,2000})\s{0,100}$""",
      """({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s{1,100}\- \[({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """exabeam_host=({host}[^\s]{1,2000})""",
      """\w+\s{1,100}\d{1,100}\s{1,100}\d\d:\d\d:\d\d\s{1,100}({host}[\w\-.]{1,2000})\s{1,100}\[""",
      """(?:[^\|]{0,2000}\|){8}({user}[^\|]{1,2000})?""",
      """(?:[^\|]{0,2000}\|){3}({app}[^\|]{1,2000})?""",
    ]
  }
```