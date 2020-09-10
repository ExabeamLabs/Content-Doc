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
    """An account failed to log on.+?Account Name:\s+(?=\w)({caller_user}.+?)\s+Account Domain:""",
    """An account failed to log on.+?Account Domain:\s+(?=\w)({caller_domain}.+?)\s+Logon ID:""",
    """Logon Type:\s+({logon_type}[\d]+)""",
    """Account For Which Logon Failed:\s+Security ID:\s+({user_sid}[^\s]+)\s+Account""",
    """Logon Failed:.+?Account Name:\s+(?=\w)({user}.+?)\s+Account Domain:""",
    """Logon Failed:.+?Account Domain:\s+(?=\w)({domain}.+?)\s+Failure Information""",
    """Sub Status:\s+({result_code}[^\s]+) """,
    """Source Network Address:\s+({src_ip}[a-fA-F:\d.]+)""",
    """Logon Process:\s+({auth_process}[^\s]+)\s+Authentication Package:\s+({auth_package}[^\s]+)""" ]
  DupFields = [ "host->dest_ip" ]
}
```