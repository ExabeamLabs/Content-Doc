#### Parser Content
```Java
{
Name = xml-4769
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = ElasticSearch
    DataType = "windows-4769"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = ["<EventID>4769</EventID>", "<Data Name='ServiceName'>"]
    Fields = [
      """SystemTime=\'({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """({event_name}A Kerberos service ticket was requested)""",
      """<Computer>({host}[^<]{1,2000})</Computer>""",
      """<EventID>({event_code}[^<]{1,2000})</EventID>""",
      """<Data Name='Status'>({result_code}[^<]{1,2000})</Data>""",
      """<Data Name='ServiceName'>({dest_host}[\w-]{1,2000})\$</Data>""",
      """<Data Name='ServiceName'>({service_name}[^<]{1,2000})</Data>""",
      """<Data Name='TicketOptions'>({ticket_options}[^<]{1,2000})</Data>""",
      """<Data Name='TicketEncryptionType'>({ticket_encryption_type}[^<]{1,2000})</Data>""",
      """<Data Name='TargetUserName'>(?=\w)({user}[^<@\s]{1,2000})(@({domain}[^<@\s]{1,2000}?))?<\/Data>""",
      """<Data Name='TargetDomainName'>(?=\w)({domain}[^<]{1,2000})</Data>""",
      """<Data Name='IpAddress'>(::[\w]{1,2000}:)?({src_ip}[a-fA-F:\d.]{1,2000})</Data>"""
    ]
  }
```