#### Parser Content
```Java
{
Name = citrix-xenapp-login
    Vendor = Citrix
    Product = Citrix XenApp
    Lms = Direct
    DataType = "app-login"
    TimeFormat = "MM/dd/yyyy:HH:mm:ss zzz"
    Conditions = [ "SSLVPN","XenApp","CTX_Application"]
    Fields = [
      """exabeam_raw=.*?({time}\d{1,100}/\d{1,100}/\d{1,100}:\d\d:\d\d:\d\d \w{3})""",
      """exabeam_raw=.*?\d{1,100}/\d{1,100}/\d{1,100}:\d\d:\d\d:\d\d \w{3}\s{1,100}({host}[^\s]{1,2000})""",
      """\s{1,100}({domain}[^\s]{1,2000})\s{1,100}User\s{1,100}""",
      """User\s{1,100}({user}.+?)\s{1,100}:""",
      """Context.+?@({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """CTX_Application=({app}.+?)&CT""",
      """CTX_AppFriendlyNameURLENcoded=({app}.+?)&CT"""
    ]
  }
```