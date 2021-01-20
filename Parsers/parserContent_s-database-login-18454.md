#### Parser Content
```Java
{
Name = s-database-login-18454
  Vendor = Microsoft
  Product = SQL Server
  Lms = Splunk
  DataType = "database-login"
  IsHVF = true
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ "EventCode=18454", "Keywords=Audit Success", "Login succeeded" ]
  Fields = [
    """exabeam_host=(.+?@\s*)?({host}[^\s]+)""",
    """\WComputerName=({host}[\w\-\.]+)\s*(\w+=|$)""",
    """({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d (AM|am|PM|pm))\s*(\w+=|$)""",
    """\WMessage=.*?\Wuser\s*'(({domain}[^\\]+)(\\)+)?({user}[^\\]+)'""",
    """\WSourceName=({service_name}.+?)\s*(\w+=|$)""",
    """\[CLIENT:\s+({src_ip}[a-fA-F\d:\.]+)\]"""
  ]
  DupFields = [ "host->dest_host" ]
}
```