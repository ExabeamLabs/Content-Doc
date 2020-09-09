#### Parser Content
```Java
{
Name = citrix-xenapp-login
    Vendor = Citrix XenApp
    Lms = Direct
    DataType = "app-login"
    TimeFormat = "MM/dd/yyyy:HH:mm:ss zzz"
    Conditions = [ "SSLVPN","XenApp","CTX_Application"]
    Fields = [
      """exabeam_raw=.*?({time}\d+/\d+/\d+:\d\d:\d\d:\d\d \w{3})""",
      """exabeam_raw=.*?\d+/\d+/\d+:\d\d:\d\d:\d\d \w{3}\s+({host}[^\s]+)""",
      """\s+({domain}[^\s]+)\s+User\s+""",
      """User\s+({user}.+?)\s+:""",
      """Context.+?@({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """CTX_Application=({app}.+?)&CT""",
      """CTX_AppFriendlyNameURLENcoded=({app}.+?)&CT"""
    ]
  }
```