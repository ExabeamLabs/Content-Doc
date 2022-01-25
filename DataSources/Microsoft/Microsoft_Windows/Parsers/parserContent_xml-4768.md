#### Parser Content
```Java
{
Name = xml-4768
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = ElasticSearch 
    DataType = "windows-4768"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = ["<EventID>4768</EventID>", "<Data Name='TargetSid'>"]
    Fields = [
      """SystemTime=\'({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """({event_name}A Kerberos authentication ticket \(TGT\) was requested)""",
      """<Computer>({host}[\w.-]{1,2000})</Computer>""",
      """<EventID>({event_code}\d{1,100})</EventID>""",
      """<Data Name='TargetSid'>(NULL SID|({user_sid}[^<]{1,2000}))</Data>""",
      """<Data Name='Status'>({result_code}[^<]{1,2000})</Data>""",
      """<Data Name='TargetUserName'>(?=\w)({user}[^<=]{1,2000})</Data>""",
      """<Data Name='TargetDomainName'>(?=\w)({domain}[^<]{1,2000})</Data>""",
      """<Data Name='IpAddress'>(::[\w]{1,2000}:)?({dest_ip}[a-fA-F:\d.]{1,2000})</Data>""",
      """<Data Name='TicketEncryptionType'>({ticket_encryption_type}[^<]{1,2000})</Data>""",
      """<Data Name='TicketOptions'>({ticket_options}[^<]{1,2000})</Data>""",
      """<Data Name='ServiceName'>({service_name}[^<]{1,2000})</Data>"""
    ]
  }
```