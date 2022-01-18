#### Parser Content
```Java
{
Name = s-xml-4697
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-service-created"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ "<EventID>4697</EventID>", "'ServiceFileName'>"]
  Fields = [ 
    """SystemTime(\\)?=\'({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """<Computer>({host}[^<]{1,2000})</Computer>""",
    """<EventID>({event_code}[^<]{1,2000})</EventID>"""
    """<Data Name(\\)?='SubjectUserSid'>(?:NONE_MAPPED|({user_sid}[^<]{1,2000}))</Data>""",
    """<Data Name(\\)?='SubjectUserName'>(?=\w)({user}[^<]{1,2000})</Data>""",
    """<Data Name(\\)?='SubjectDomainName'>(?=\w)({domain}[^<]{1,2000})</Data>""",
    """<Data Name(\\)?='SubjectLogonId'>(?=\w)({logon_id}[^<]{1,2000})</Data>""",
    """<Data Name(\\)?='ServiceName'>(?=\w)({service_name}[^<]{1,2000})</Data>""",
    """<Data Name(\\)?='ServiceAccount'>(?=\w)(({account_domain}[^\\<]{0,2000})\\)?({account_name}[^<]{1,2000})</Data>""",
    """<Data Name(\\)?='ServiceFileName'>"?(?=\w)({process}({directory}(?:(\w+:)?[^:<"]{1,2000})?[\\\/])?({process_name}[^<"]{1,2000}))""",
    """<Data Name(\\)?='ServiceType'>(?=\w)({service_type}[^<]{1,2000})</Data>"""
  ]
  DupFields = [ "host->dest_host", "directory->process_directory" ]


}
```