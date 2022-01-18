#### Parser Content
```Java
{
Name = xml-5861
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-audit"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """<EventID>5861""" , """Microsoft-Windows-WMI-Activity"""]
  Fields = [
    """SystemTime=\'({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """<EventID>({event_code}[^<]{1,2000})</EventID>""",
    """<Computer>({host}[^<]{1,2000})</Computer>""",
    """<Security UserID='({user_sid}[^']{1,2000})""",
    """({process_name}WMI)""",
    """Query\s{0,100}=\s{0,100}"{0,20}({command_line}[^";]{1,2000})""",
    """Consumer:\s{0,100} instance of\s{0,100}({process}.+?)\s{0,100}\{"""
  ]
  DupFields = [ "host->dest_host" ]


}
```