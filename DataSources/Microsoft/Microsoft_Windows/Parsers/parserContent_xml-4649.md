#### Parser Content
```Java
{
Name = xml-4649
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """<EventID>4649</EventID>""", """A replay attack was detected""" ]
  Fields = [
    """<EventRecordID>({record_id}[^<]{1,2000})<\/EventRecordID>""",
    """ThreadID='({thread_id}[^']{1,2000})""",
    """Account Domain:\s{0,100}(NT AUTHORITY|({domain}\S+))\s{1,100}Logon ID:""",
    """<Computer>({host}[^<>]{1,2000})<\/Computer>""",
    """<Execution ProcessID='({process_id}[^']{1,2000})""",
    """ProcessID='({process_id}\d{1,100})""",
    """Name='LogonProcessName'>({auth_process}[^<]{1,2000})""",
    """<Message>({event_name}.+?)\s{0,100}\.(\s|</Message>)""",
    """<Message>({event_name}.+?)\s{1,100}Subject:""",
    """<Keywords?>({outcome}[^<]{1,2000})<\/Keywords?>""",
    """<Provider>({provider_name}.+?)</Provider>""",
    """<Correlation ActivityID='\{({activity_id}[^\}']{1,2000})""",
    """ActivityID='\{?({activity_id}[^\}']{1,2000})""",
    """Security ID:\s{0,100}({user_sid}\S+)\s{1,100}Account Name:""",
    """<TimeCreated SystemTime='({time}\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d)""",
    """Logon ID:\s{0,100}({logon_id}\S+)\s{1,100}""",
    """Account Name:\s{0,100}(LOCAL SERVICE|({user}\S+))\s{1,100}Account Domain:""",
    """<EventID>({event_code}[^<]{1,2000})<\/EventID>""",
    """({additiona_info}Credentials Which Were Replayed:.+)This event indicates that a Kerberos replay attack was detected""",
  ]
  DupFields = [ "event_name->alert_name", "auth_process->alert_type" ]
}
```