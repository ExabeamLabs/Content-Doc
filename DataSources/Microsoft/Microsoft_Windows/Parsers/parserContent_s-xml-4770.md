#### Parser Content
```Java
{
Name = s-xml-4770
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-4770"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ "<EventID>4770</EventID>", "<Data Name='IpAddress'>"]
  Fields = [ """SystemTime=\'({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """<Computer>({host}[^<]{1,2000})</Computer>""",
    """<EventID>({event_code}[^<]{1,2000})</EventID>""",
    """<Data Name='TargetSid'>(?:NONE_MAPPED|({user_sid}[^<]{1,2000}))</Data>""",
    """<Data Name='TargetUserName'>(?=\w)({user}[^<@\s]{1,2000})</Data>""",
    """<Data Name='TargetUserName'>(?=\w)({user_email}[^<@\s]{1,2000}@[^<@\s]{1,2000})</Data>""",
    """<Data Name='TargetDomainName'>(?=\w)({domain}[^<]{1,2000})</Data>""",
    """<Data Name='IpAddress'>(::\w+:)?({src_ip}[a-fA-F:\d.]{1,2000})</Data>""",
    """<Data Name='ServiceName'>({service_name}[^<]{1,2000})</Data>""",
    """<Data Name='ServiceName'>({dest_host}[^<]{1,2000}\$)</Data>""",
    """<Data Name='TicketOptions'>({ticket_options}[^<]{1,2000})</Data>""",
    """<Data Name='TicketEncryptionType'>({ticket_encryption_type}[^<]{1,2000})</Data>"""
  ]
}
```