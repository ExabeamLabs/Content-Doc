#### Parser Content
```Java
{
Name = cyberark-privileged-access
  Vendor = CyberArk
  Product = Endpoint Privilege Management
  Lms = Direct
  DataType = "privileged-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """CyberArk-EPM-Event {""", """'eventType': 'ElevationRequest'""", """'sourceType':""" ]
  Fields = [
    """'arrivalTime':\s'({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{0,3})?Z)'""",
    """'userName':\s'((\.|({domain}[^'\\]{1,2000}))\\{1,20})?({user}[^'\\]{1,2000})'""",
    """'eventType':\s'({event_name}[^']{1,2000})'""",
    """'originalFileName':\s'({file_name}[^']{1,2000}?(\.({file_ext}[^'\.]{1,2000}))?)'""",
    """'filePath':\s'({file_path}[^']{1,2000})'""",
    """'fileSize':\s({file_size}\d{1,20})""",
    """'commandLine':\s'({command_line}[^']{1,2000})'""",
    """'fileDescription':\s'({additional_info}[^']{1,2000})'""",    
    """'displayName':\s'({additional_info}[^']{1,2000})'"""
  ]
  DupFields = [ "event_name->activity" ]


}
```