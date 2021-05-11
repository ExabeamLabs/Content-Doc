#### Parser Content
```Java
{
Name = s-612
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-audit"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ "EventCode=612", "Audit Policy Change:" ]
  Fields = [
    """({event_name}Audit Policy Change)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[^\s]+)""",
    """ComputerName=({host}[\w.\-]+)""",
    """({event_code}612)""",
    """Changed By:.*\s{1,100}User Name:\s{1,100}({user}[^\s]+)"""
    """\s{1,100}Domain Name:\s{1,100}({domain}[^\s]+)""",
    """\s{1,100}Logon ID:\s{1,100}\([^,]+,({logon_id}[^)]+)""",
    """Policy Change:\s{1,100}New Policy:(({policy}[^\n]+)\n+)+\s{0,100}Changed By:"""
  ]
  DupFields = [ "host->dest_host" ]
}
```