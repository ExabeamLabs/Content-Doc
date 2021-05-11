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
    """<EventID>({event_code}[^<]+)</EventID>""",
    """<Computer>({host}[^<]+)</Computer>""",
    """<Security UserID='({user_sid}[^']+)""",
    """({process_name}WMI)""",
    """Query\s{0,100}=\s{0,100}"{0,20}({command_line}[^";]+)""",
    """Consumer:\s{0,100} instance of\s{0,100}({process}.+?)\s{0,100}\{"""
  ]
  DupFields = [ "host->dest_host" ]
}
```