#### Parser Content
```Java
{
Name = xml-sysmon-alert
  Vendor = Microsoft
  Product = Sysmon
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """<Provider Name ='Microsoft-Windows-Sysmon'""", """<EventID>25</EventID>""", """<Data Name ='Image'>""","""Process Tampering""" ]
  Fields = [
    """<TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """<Computer>({host}[\w\-.]{1,2000})""",
    """<EventID>({event_code}25)""",
    """ProcessID='({pid}\d{1,100})'""",
    """ThreadID='({thread_id}\d{1,100})'""",
    """<Security UserID='({user_sid}[^']{1,2000})'""",
    """Guid='\{({process_guid}[^'}]{1,2000})""",
    """({alert_name}Process Tampering)""",
    """<Data Name ='Image'>({process}({directory}[^<>"]{0,2000}?[\\\/]{1,2000})?({process_name}[^"<>\\\/]{0,2000}))<\/Data>"""
  ]
  DupFields = ["directory->process_directory","pid->process_id","host->dest_host"]


}
```