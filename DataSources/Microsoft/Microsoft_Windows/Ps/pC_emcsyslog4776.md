#### Parser Content
```Java
{
Name = emc-syslog-4776
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-4776"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "__li_source_path=", "attempted to validate the credentials for an account","""eventid="4776""""]
  Fields = [
    """({event_name}The (computer|domain controller) attempted to validate the credentials for an account)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """__li_source_path="({host}[^"]{1,2000})"""",
    """Source Workstation:\s{0,100}(\\+)?(({dest_ip}[A-Fa-f:\d.]{1,2000})|(?:(?!NULL)({dest_host}[^\s]{1,2000})))?(:\d{1,100})?\s{0,100}Error Code:""",
    """({event_code}4776)""",
    """Logon (?:a|A)ccount:\s{1,100}({user}[^@]{1,2000}?)(?:@({domain}[^\s.]{1,2000})[^\s]{0,2000})?\s{1,100}Source Workstation""",
    """Error Code:\s{1,100}({result_code}[\w\-]{1,2000})""",
     ]


}
```