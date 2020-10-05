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
    """Query\s*=\s*"*({command_line}[^";]+)""",
    """Consumer:\s* instance of\s*({process}.+?)\s*\{"""
  ]
  DupFields = [ "host->dest_host" ]
}
```