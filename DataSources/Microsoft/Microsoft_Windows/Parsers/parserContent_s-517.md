#### Parser Content
```Java
{
Name = s-517
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-audit"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ "EventCode=517", "The audit log was cleared" ]
  Fields = [
    """({event_name}The audit log was cleared)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[^\s]{1,2000})""",
    """ComputerName=({host}[\w.\-]{1,2000})""",
    """Client User Name:\s{1,100}({user}[^\s]{1,2000})""",
    """({event_code}517)""",
    """\s{1,100}Client Domain:\s{1,100}({domain}[^\s]{1,2000})""",
    """\s{1,100}Client Logon ID:\s{1,100}\([^,]{1,2000}
```