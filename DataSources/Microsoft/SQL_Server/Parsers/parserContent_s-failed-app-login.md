#### Parser Content
```Java
{
Name = s-failed-app-login
  Vendor = Microsoft
  Product = SQL Server
  Lms = Splunk
  DataType = "failed-app-login"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ "EventCode=18456", "Keywords=Audit Failure", "Login failed" ]
  Fields = [
    """exabeam_host=(.+?@\s*)?({host}[^\s]+)""",
    """\WComputerName=({host}[\w\-\.]+)\s*(\w+=|$)""",
    """({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d (AM|am|PM|pm))\s*(\w+=|$)""",
    """\WMessage=.*?\Wuser\s*'(({domain}[^\\]+)(\\)+)?({user}[^\\]+)'""",
    """\WSourceName=({service_name}.+?)\s*(\w+=|$)""",
    """\[CLIENT:\s+({src_ip}[a-fA-F\d:\.]+)\]""",
    """\WReason:\s*({failure_reason}.+?)\s*\["""
  ]
  DupFields = [ "host->dest_host" ]
}
```