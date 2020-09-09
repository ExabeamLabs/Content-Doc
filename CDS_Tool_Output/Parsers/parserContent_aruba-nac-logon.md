#### Parser Content
```Java
{
Name = aruba-nac-logon
    Vendor = HP Aruba
    Lms = Splunk
    DataType = "nac-logon"
    TimeFormat = "MMM dd HH:mm:ss yyyy"
    Conditions = ["User Authentication Successful: username=", "AAA profile=", "exabeam_raw"]
    Fields = [
      """exabeam_raw=({time}\w+ \d+ \d+:\d+:\d+ \d\d\d\d)\s+({host}[^\s]+)\s+authmgr\[""",
      """User Authentication Successful: username=(?:({user_type}host)/)?({user}.+?)(?:([0-9A-F:]{17})?@[^\s]+)?\s+MAC=""",
      """\sIP=({dest_ip}[^\s]+).+?\sSSID=({network}[^\s]+)""",
      """\sauth server=({auth_server}[^\s]+)"""]
  }
```