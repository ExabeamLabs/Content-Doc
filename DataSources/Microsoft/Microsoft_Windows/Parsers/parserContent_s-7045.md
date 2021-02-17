#### Parser Content
```Java
{
Name = s-7045
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-service-created"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ " EventCode=7045", "A service was installed in the system." ]
  Fields = [
    """({event_name}A service was installed in the system)""",
    """({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d (am|AM|pm|PM))\s+LogName=""",
    """({event_code}7045)""",
    """ComputerName=({host}[^\s]+)""",
    """User=\s*({user}.+?)\s+Sid=({user_sid}[^\s]+)""",
    """Service Name:\s+({service_name}.+?)\s+Service File Name:""",
    """Service File Name:\s+(|-|({process}({directory}(?:[^"]+)?[\\\/])?({process_name}[^\\\/\s]+)))\s+Service Type:""",
    """Service Type:\s+({service_type}.+?)\s+Service Start Type:""",
    """Service Account:\s+({account_name}.+?)\s*(\w+=|$)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```