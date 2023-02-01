#### Parser Content
```Java
{
Name = s-json-4697-1
  Vendor = Microsoft
  Product = Windows
  Lms = Splunk
  DataType = "windows-service-created"
  TimeFormat = "epoch"
  Conditions = [ """"event_id":4697""", """A service was installed in the system""", """"provider":"Microsoft-Windows-Security-Auditing"""", """"message":""" ]
  Fields = [
    """"timestamp":({time}\d{1,2000})""",
    """({event_code}4697)""",
    """({event_name}A service was installed in the system)""",
    """"hostname":"({host}[^"]{1,2000})"""",
    """"keywords":[\["]{0,100}({outcome}[^"\]]{1,2000})""",
    """"SubjectUserSid":"({user_sid}[^"]{1,2000})"""",
    """"SubjectUserName":"({user}[^"]{1,2000})"""",
    """"SubjectDomainName":"({domain}[^"]{1,2000})"""",
    """"SubjectLogonId":"({logon_id}[^"]{1,2000})"""",
    """"ServiceName":"({service_name}[^"]{1,2000})"""",
    """"ServiceFileName":"\s{0,100}(|({process}({directory}.*?[\\\/]{1,2000})?({process_name}[^\\\/]{1,2000}?)))"""",
    """"ServiceType":"({service_type}[^"]{1,2000})"""",
    """"ServiceStartType":"({service_start_type}[^"]{1,2000})"""",
    """"ServiceAccount":"({account_domain}[^"]{1,2000})"""",
    """"pid":({process_id}\d{1,100})"""
  ]
  DupFields = [ "host->dest_host", "directory->process_directory" ]


}
```