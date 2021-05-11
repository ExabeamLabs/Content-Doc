#### Parser Content
```Java
{
Name = emc-syslog-4625
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-failed-logon"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "__li_source_path=", "An account failed to log on","""eventid="4625"""" ]
  Fields = [
    """({event_name}An account failed to log on)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """__li_source_path="({host}[^"]+)"""",
    """({event_code}4625)""",
    """An account failed to log on.+?Account Name:\s{1,100}(?=\w)({caller_user}.+?)\s{1,100}Account Domain:""",
    """An account failed to log on.+?Account Domain:\s{1,100}(?=\w)({caller_domain}.+?)\s{1,100}Logon ID:""",
    """Logon Type:\s{1,100}({logon_type}[\d]+)""",
    """Account For Which Logon Failed:\s{1,100}Security ID:\s{1,100}({user_sid}[^\s]+)\s{1,100}Account""",
    """Logon Failed:.+?Account Name:\s{1,100}(?=\w)({user}.+?)\s{1,100}Account Domain:""",
    """Logon Failed:.+?Account Domain:\s{1,100}(?=\w)({domain}.+?)\s{1,100}Failure Information""",
    """Sub Status:\s{1,100}({result_code}[^\s]+) """,
    """Source Network Address:\s{1,100}({src_ip}[a-fA-F:\d.]+)""",
    """Logon Process:\s{1,100}({auth_process}[^\s]+)\s{1,100}Authentication Package:\s{1,100}({auth_package}[^\s]+)""" ]
  DupFields = [ "host->dest_ip" ]
}
```