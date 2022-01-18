#### Parser Content
```Java
{
Name = mcafee-siem-process-created
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-process-created"
    IsHVF = true
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
    Conditions = [ """McAfee_SIEM:""", """A new process has been created""" ]
    Fields = [
      """({event_name}A new process has been created)""",
      """"src_ip":"({src_ip}[^"]{1,2000})""",
      """"dst_ip":"({dest_ip}[^"]{1,2000})""",
      """"id":\d{0,100}({event_code}4688)""",
      """"firsttime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
      """"DomainID":"({domain}[^"]{1,2000})""",
      """"HostID":"({host}[^"]{1,2000})""",
      """"UserIDSrc":"({user}[^"]{1,2000})""",
      """"Security_ID":"({user_sid}[^"]{1,2000})""",
      """"Process_Name":"({process}({directory}[^"]{0,2000}?)(\\u005|[\\\/])*({process_name}[^\\\/"]{1,2000}?))"""",
      """"Source_Logon_ID":"({logon_id}[^"]{1,2000})"""
    ]
    DupFields = [ "host->dest_host", "directory->process_directory" ]
  

}
```