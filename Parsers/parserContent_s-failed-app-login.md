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
    """exabeam_host=(.+?@\s*)?({host}[^\s]+)""",
    """(\\n|\W)ComputerName=({host}[\w\-\.]+)\s*(\\n)?(\w+=|$)""",
    """({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d (?i)(AM|PM))""",
    """(\\n|\W)Message=[^=]*?\Wuser\s*'\s*(({domain}[^\\]+)(\\)+)?({user}[^\\]+)'""",
    """(\\n|\W)SourceName=({service_name}[^=]+?)\s*(\\n)?(\w+=|$)""",
    """SourceName=({app}MSSQL)""",
    """\[CLIENT:\s+({src_ip}[a-fA-F\d:\.]+)\]""",
    """\WReason:\s*({failure_reason}[^:]+?)\s*\[""",
    """source_hostname":"({src_host}[^"]+)""",
    """EventCode=({event_code}\d+)""",
    """({event_name}Login failed)""",
  ]
  DupFields = [ "host->dest_host" ]
}
```