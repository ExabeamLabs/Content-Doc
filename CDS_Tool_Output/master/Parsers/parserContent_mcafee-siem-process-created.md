#### Parser Content
```Java
{
Name = mcafee-siem-process-created
    Vendor = Microsoft
    Product = Windows
    Lms = Direct
    DataType = "windows-process-created"
    IsHVF = true
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
    Conditions = [ """McAfee_SIEM:""", """A new process has been created""" ]
    Fields = [
      """({event_name}A new process has been created)""",
      """"src_ip":"({src_ip}[^"]+)""",
      """"dst_ip":"({dest_ip}[^"]+)""",
      """"id":\d*({event_code}4688)""",
      """"firsttime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
      """"DomainID":"({domain}[^"]+)""",
      """"HostID":"({host}[^"]+)""",
      """"UserIDSrc":"({user}[^"]+)""",
      """"Security_ID":"({user_sid}[^"]+)""",
      """"Process_Name":"({process}({directory}[^"]*?)(\\u005|[\\\/])*({process_name}[^\\\/"]+?))"""",
      """"Source_Logon_ID":"({logon_id}[^"]+)"""
    ]
    DupFields = [ "host->dest_host", "directory->process_directory" ]
  }
```