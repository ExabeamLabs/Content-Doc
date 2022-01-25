#### Parser Content
```Java
{
Name = raw-7045
  Vendor = Microsoft
  Product = Windows
  Lms = Direct
  DataType = "windows-service-created"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ """7045""", """A service was installed in the system.""" ]
  Fields = [
    """EventTime":"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)"""",
    """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",   
    """({event_name}A service was installed in the system)""",
    """ComputerName =({host}[\w-.]{1,2000})\s""",
    """\WComputer=({host}[\w\-.]{1,2000})\s""",
    """({host}\S+)\sEvntSLog""",
    """({time}\d\d\/\d\d\/\d\d\d\d\s{1,100}\d\d:\d\d:\d\d\s{1,100}(?i)(AM|PM))""",
    """\]\s{1,100}\w{3}\s({time}\w{3}\s\d{1,100}\s\d\d:\d\d:\d\d\s\d\d\d\d)""",
    """TimeGenerated=({time}\d{1,10})""",
    """({event_code}7045)""",
    """AccountName":"((?i)SYSTEM|NOT_TRANSLATED|({user}[^"]{1,2000}))"""",
    """User=((?i)NOT_TRANSLATED|({user}[^\s]{1,2000}))""",
    """\w{3}\s\w{3}\s\d\d\s\d\d:\d\d:\d\d\s\d\d\d\d:\s({domain}[^\\]{1,2000})\\(\\)?((?i)NOT_TRANSLATED|({user}[^\/]{1,2000}))""",
    """Service Name:\s{1,100}({service_name}[^=:]{1,2000}?)\s{0,100}Service File Name:""",
    """Service File Name:\s{1,100}(|-|({process}({directory}(?:[^"]{1,2000})?[\\\/])?({process_name}[^\\\/\s]{1,2000})))\s{1,100}Service Type:""",
    """Service File Name:\s{0,100}((?:[^";]{1,2000})?[\\\/;])?({process_name}[^\\\/";]{1,2000}?\.[^\\\/\.;"]{1,2000}?)\s.*?\s{0,100}Service Type:""",
    """Service Type:\s{1,100}({service_type}[^=:]{1,2000}?)\s{0,100}Service Start Type:""",
    """Service Account:\s{0,100}(|(({account_domain}[^\\]{1,2000})\\)?({account_name}[^"]{1,2000}?))\s{0,100}("|$)""",
    """Service File Name:\s{0,100}({command_line}[^=]{1,2000}?)\s{0,100}Service Type:""",
    """ComputerName(:|=)\s{0,100}({host}[\w.-]{1,2000})""",
    """TimeStamp:\s{0,100}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """User:\s{0,100}((?i)NOT_TRANSLATED|({user}[^:]{1,2000}?))\s{0,100}\w+:"""
  ]
  DupFields = [ "host->dest_host", "directory->process_directory", "command_line->service_command_line"]


}
```