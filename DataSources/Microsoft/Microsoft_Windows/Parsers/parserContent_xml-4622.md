#### Parser Content
```Java
{
Name = xml-4622
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Syslog
  DataType = "service-created"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """<EventID>4622<""", """<Provider Name='Microsoft-Windows-Security-Auditing'""", """A security package has been loaded by the Local Security Authority""" ]
  Fields = [
    """<EventID>({event_code}\d{1,100})""",
    """<TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """<Computer>({host}[^<]+)""",
    """<Keyword>({outcome}[^<]+)<\/Keyword>""",
    """<EventRecordID>({record_id}[^<]+)<\/EventRecordID>""",
    """<Message>({event_name}[^<]+)<\/Message>""",
    """Message>.*?<Task>({activity}.*?)<\/Task>""",
    """<Provider Name='Microsoft-Windows-Security-Auditing' Guid='\{({process_guid}[^}]+?)\}""",
    """<Correlation ActivityID='\{({activity_id}[^\}']+)""",
    """<Execution ProcessID='({process_id}[^']+)""",
    """ThreadID='({thread_id}[^']+)""",
    """<Provider>({provider_name}.+?)<\/Provider>""",
    """<Data Name='SecurityPackageName'>({service_name}[^<]+)<""",
  ]
  DupFields = ["host->dest_host"]
}
```