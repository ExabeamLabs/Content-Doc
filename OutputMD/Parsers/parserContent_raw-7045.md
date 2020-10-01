#### Parser Content
```Java
{
Name = raw-7045
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-service-created"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ """7045""", """A service was installed in the system.""" ]
  Fields = [
    """({event_name}A service was installed in the system)""",
    """({host}\S+)\sEvntSLog""",
    """\]\s+\w{3}\s({time}\w{3}\s\d+\s\d\d:\d\d:\d\d\s\d\d\d\d)""",
    """({event_code}7045)""",
    """\w{3}\s\w{3}\s\d\d\s\d\d:\d\d:\d\d\s\d\d\d\d:\s({domain}[^\\]+)\\(\\)?({user}[^\/]+)""",
    """Service Name:\s+({service_name}.+?)\s+Service File Name:""",
    """Service File Name:\s+(|-|({process}({directory}(?:[^"]+)?[\\\/])?({process_name}[^\\\/\s]+)))\s+Service Type:""",
    """Service Type:\s+({service_type}.+?)\s+Service Start Type:""",
    """Service Account:\s+({account_name}[^"\\]+)"""
  ]
  DupFields = [ "host->dest_host", "directory->process_directory" ]
}
```