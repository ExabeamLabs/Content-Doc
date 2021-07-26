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
    """({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d (am|AM|pm|PM))\s{1,100}LogName=""",
    """({event_code}7045)""",
    """ComputerName=({host}[^\s]{1,2000})""",
    """User=\s{0,100}({user}.+?)\s{1,100}Sid=({user_sid}[^\s]{1,2000})""",
    """Service Name:\s{1,100}({service_name}.+?)\s{1,100}Service File Name:""",
    """Service File Name:\s{1,100}(|-|({process}({directory}(?:[^"]{1,2000})?[\\\/])?({process_name}[^\\\/\s]{1,2000})))\s{1,100}Service Type:""",
    """Service Type:\s{1,100}({service_type}.+?)\s{1,100}Service Start Type:""",
    """Service Account:\s{1,100}({account_name}.+?)\s{0,100}(\w+=|$)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```