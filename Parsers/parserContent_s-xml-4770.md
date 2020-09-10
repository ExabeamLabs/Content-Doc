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
    """<Computer>({host}[^<]+)</Computer>""",
    """<EventID>({event_code}[^<]+)</EventID>""",
    """<Data Name='TargetSid'>(?:NONE_MAPPED|({user_sid}[^<]+))</Data>""",
    """<Data Name='TargetUserName'>(?=\w)({user}[^<@\s]+)</Data>""",
    """<Data Name='TargetUserName'>(?=\w)({user_email}[^<@\s]+@[^<@\s]+)</Data>""",
    """<Data Name='TargetDomainName'>(?=\w)({domain}[^<]+)</Data>""",
    """<Data Name='IpAddress'>(::\w+:)?({src_ip}[a-fA-F:\d.]+)</Data>""",
    """<Data Name='ServiceName'>({service_name}[^<]+)</Data>""",
    """<Data Name='ServiceName'>({dest_host}[^<]+\$)</Data>""",
    """<Data Name='TicketOptions'>({ticket_options}[^<]+)</Data>""",
    """<Data Name='TicketEncryptionType'>({ticket_encryption_type}[^<]+)</Data>"""
  ]
}
```