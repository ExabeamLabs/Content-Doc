#### Parser Content
```Java
{
Name = s-failed-app-login
  Vendor = Microsoft
  Product = Microsoft SQL Server
  Lms = Direct 
  DataType = "failed-app-login"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ "EventCode=18456", "Keywords=Audit Failure", "Login failed" ]
  Fields = [
    """exabeam_host=(.+?@\s{0,100})?({host}[^\s]{1,2000})""",
    """(\\n|\W)ComputerName=({host}[\w\-\.]{1,2000})\s{0,100}(\\n)?(\w+=|$)""",
    """({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d (?i)(AM|PM))""",
    """(\\n|\W)Message=[^=]{0,2000}?\Wuser\s{0,100}'\s{0,100}(({domain}[^\\]{1,2000})(\\)+)?({user}[^\\]{1,2000})'""",
    """(\\n|\W)SourceName=({service_name}[^=]{1,2000}?)\s{0,100}(\\n)?(\w+=|$)""",
    """SourceName=({app}MSSQL)""",
    """\[CLIENT:\s{1,100}({src_ip}[a-fA-F\d:\.]{1,2000})\]""",
    """\WReason:\s{0,100}({failure_reason}[^:]{1,2000}?)\s{0,100}\[""",
    """source_hostname":"({src_host}[^"]{1,2000})""",
    """EventCode=({event_code}\d{1,100})""",
    """({event_name}Login failed)""",
  ]
  DupFields = [ "host->dest_host" ]
}
```