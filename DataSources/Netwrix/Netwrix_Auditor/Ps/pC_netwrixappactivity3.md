#### Parser Content
```Java
{
Name = netwrix-app-activity-3
  Conditions = [ """NetWrix""", """>1003</EventID>""", """The following audit event was detected:""" ]
}
netwrix-app-activity = {
  Vendor = Netwrix
  Product = Netwrix Auditor
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Fields = [
    """When:\s{0,100}({time}\d{1,100}\/\d{1,100}\/\d\d\d\d \d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM))""",
    """Who:\s{0,100}(({domain}[^\\\s]{1,2000})\\+)?({user}[^\s\\]{1,2000})""",
    """What:\s{0,100}({resource}.+?)({object}[^\\]{1,2000}?)\s{1,100}When:""",
    """Where:\s{0,100}(unknown|({dest_host}[\w\-.]{1,2000}))""",
    """Change type:\s{0,100}({activity}.+?)\s{1,100}Object type:""",
    """Object type:\s{0,100}({additional_info}\S+)""",
    """Monitoring Plan:\s{0,100}({monitoring_plan}.+?)\s{1,100}Detected by:""",
    """Detected by:\s{0,100}({host}[\w\-.]{1,2000})""",
    """>({event_code}[^\<]{1,2000})<\/EventID>""",
    """<EventRecordID>({record_id}[^\<]{1,2000})<\/EventRecordID>""",
  ]}
```