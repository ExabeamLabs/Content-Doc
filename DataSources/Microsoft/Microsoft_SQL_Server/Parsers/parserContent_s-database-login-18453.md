#### Parser Content
```Java
{
Name = s-database-login-18453
  Vendor = Microsoft
  Product = Microsoft SQL Server
  Lms = Splunk
  DataType = "database-login"
  IsHVF = true
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ "EventCode=18453", "Keywords=Audit Success", "Login succeeded" ]
  Fields = [
    """exabeam_host=(.+?@\s{0,100})?({host}[^\s]+)""",
    """\WComputerName=({host}[\w\-\.]+)\s{0,100}(\w+=|$)""",
    """({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d (AM|am|PM|pm))\s{0,100}(\w+=|$)""",
    """\WMessage=.*?\Wuser\s{0,100}'(({domain}[^\\]+)(\\)+)?({user}[^\\]+)'""",
    """\WSourceName=({service_name}.+?)\s{0,100}(\w+=|$)""",
    """\[CLIENT:\s{1,100}({src_ip}[a-fA-F\d:\.]+)\]"""
  ]
  DupFields = [ "host->dest_host" ]
}
```