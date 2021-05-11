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
    """ComputerName=({host}[\w-.]+)\s""",
    """({host}\S+)\sEvntSLog""",
    """({time}\d\d\/\d\d\/\d\d\d\d\s{1,100}\d\d:\d\d:\d\d\s{1,100}(?i)(AM|PM))""",
    """\]\s{1,100}\w{3}\s({time}\w{3}\s\d{1,100}\s\d\d:\d\d:\d\d\s\d\d\d\d)""",
    """({event_code}7045)""",
    """User=({user}[^\s]+)""",
    """\w{3}\s\w{3}\s\d\d\s\d\d:\d\d:\d\d\s\d\d\d\d:\s({domain}[^\\]+)\\(\\)?({user}[^\/]+)""",
    """Service Name:\s{1,100}({service_name}.+?)\s{1,100}Service File Name:""",
    """Service File Name:\s{1,100}(|-|({process}({directory}(?:[^"]+)?[\\\/])?({process_name}[^\\\/\s]+)))\s{1,100}Service Type:""",
    """Service File Name:\s{0,100}((?:[^";]+)?[\\\/;])?({process_name}[^\\\/";]+?\.[^\\\/\.;"]+?)\s.*?\s{0,100}Service Type:""",
    """Service Type:\s{1,100}({service_type}.+?)\s{1,100}Service Start Type:""",
    """Service Account:\s{1,100}({account_name}[^"\\]+)""",
    """Service File Name:\s{0,100}({command_line}.*)\s{1,100}Service Type:""",
    """ComputerName(:|=)\s{0,100}({host}[\w.-]+)""",
    """TimeStamp:\s{0,100}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """User:\s{0,100}({user}.+?)\s{0,100}\w+:"""
  ]
  DupFields = [ "host->dest_host", "directory->process_directory", "command_line->service_command_line"]
}
```