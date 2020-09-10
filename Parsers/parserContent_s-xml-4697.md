#### Parser Content
```Java
{
Name = s-xml-4697
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-service-created"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ "<EventID>4697</EventID>", "<Data Name='ServiceFileName'>"]
  Fields = [ """SystemTime=\'({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """<Computer>({host}[^<]+)</Computer>""",
    """<EventID>({event_code}[^<]+)</EventID>"""
    """<Data Name='SubjectUserSid'>(?:NONE_MAPPED|({user_sid}[^<]+))</Data>""",
    """<Data Name='SubjectUserName'>(?=\w)({user}[^<]+)</Data>""",
    """<Data Name='SubjectDomainName'>(?=\w)({domain}[^<]+)</Data>""",
    """<Data Name='SubjectLogonId'>(?=\w)({logon_id}[^<]+)</Data>""",
    """<Data Name='ServiceName'>(?=\w)({service_name}[^<]+)</Data>""",
    """<Data Name='ServiceAccount'>(?=\w)(({account_domain}[^\\<]*)\\)?({account_name}[^<]+)</Data>""",
    """<Data Name='ServiceFileName'>"?(?=\w)({process}({directory}(?:(\w+:)?[^:<"]+)?[\\\/])?({process_name}[^<"]+))""",
    """<Data Name='ServiceType'>(?=\w)({service_type}[^<]+)</Data>"""
  ]
  DupFields = [ "host->dest_host", "directory->process_directory" ]
}
```