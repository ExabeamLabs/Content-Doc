#### Parser Content
```Java
{
Name = xml-5478
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Syslog
  DataType = "service-created"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """<EventID>5478<""", """<Provider Name ='Microsoft-Windows-Security-Auditing'""", """The IPsec Policy Agent service was started""" ]
  Fields = [
    """<EventID>({event_code}\d{1,100})""",
    """<TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """<Computer>({host}[^<]{1,2000})""",
    """<Keyword>({outcome}[^<]{1,2000})<\/Keyword>""",
    """<EventRecordID>({record_id}[^<]{1,2000})<\/EventRecordID>""",
    """<Message>({event_name}[^<]{1,2000})<\/Message>""",
    """Message>.*?<Task>({activity}.*?)<\/Task>""",
    """<Provider Name ='Microsoft-Windows-Security-Auditing' Guid='\{({process_guid}[^}]{1,2000}?)\}""",
    """<Correlation ActivityID='\{({activity_id}[^\}']{1,2000})""",
    """<Execution ProcessID='({process_id}[^']{1,2000})""",
    """ThreadID='({thread_id}[^']{1,2000})""",
    """<Provider>({provider_name}.+?)<\/Provider>""",
    """({service_name}IPsec Policy Agent)"""
  ]
  DupFields = ["host->dest_host"]


}
```