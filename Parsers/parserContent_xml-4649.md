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
    """<EventRecordID>({record_id}[^<]+)<\/EventRecordID>""",
    """ThreadID='({thread_id}[^']+)""",
    """Account Domain:\s*(NT AUTHORITY|({domain}\S+))\s+Logon ID:""",
    """<Computer>({host}[^<>]+)<\/Computer>""",
    """<Execution ProcessID='({process_id}[^']+)""",
    """ProcessID='({process_id}\d+)""",
    """Name='LogonProcessName'>({auth_process}[^<]+)""",
    """<Message>({event_name}.+?)\s*\.(\s|</Message>)""",
    """<Message>({event_name}.+?)\s+Subject:""",
    """<Keywords?>({outcome}[^<]+)<\/Keywords?>""",
    """<Provider>({provider_name}.+?)</Provider>""",
    """<Correlation ActivityID='\{({activity_id}[^\}']+)""",
    """ActivityID='\{?({activity_id}[^\}']+)""",
    """Security ID:\s*({user_sid}\S+)\s+Account Name:""",
    """<TimeCreated SystemTime='({time}\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d)""",
    """Logon ID:\s*({logon_id}\S+)\s+""",
    """Account Name:\s*(LOCAL SERVICE|({user}\S+))\s+Account Domain:""",
    """<EventID>({event_code}[^<]+)<\/EventID>""",
    """({additiona_info}Credentials Which Were Replayed:.+)This event indicates that a Kerberos replay attack was detected""",
  ]
  DupFields = [ "event_name->alert_name", "auth_process->alert_type" ]
}
```