#### Parser Content
```Java
{
Name = xml-4622
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Syslog
  DataType = "service-created"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """<EventID>4622<""", """<Provider Name ='Microsoft-Windows-Security-Auditing'""", """A security package has been loaded by the Local Security Authority""" ]
  Fields = [
    """({event_code}4622)""",
    """<TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """<Computer>({host}[^<]{1,2000})""",
    """<Keyword>({outcome}[^<]{1,2000})<\/Keyword>""",
    """<EventRecordID>({record_id}[^<]{1,2000})<\/EventRecordID>""",
    """({event_name}A security package has been loaded by the Local Security Authority)""",
    """Message>[^\]\}]{0,2000}?<Task>({activity}[^<]{1,2000}?)<""",
    """<Provider Name ='Microsoft-Windows-Security-Auditing' Guid='\{({process_guid}[^}]{1,2000}?)\}""",
    """<Correlation ActivityID='\{({activity_id}[^\}']{1,2000})""",
    """<Execution ProcessID='({process_id}[^']{1,2000})""",
    """ThreadID='({thread_id}[^']{1,2000})""",
    """<Provider>({provider_name}[^<]{1,2000}?)<""",
    """<Data Name ='SecurityPackageName'>({service_name}[^<]{1,2000})<""",
  ]
  DupFields = ["host->dest_host"]


}
```