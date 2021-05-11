#### Parser Content
```Java
{
Name = json-xml-4769
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-4769"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = [ """"EventID":"4769"""", """<Data Name='""" ]
    Fields = [
      """"TimeGenerated":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """"EventID":"({event_code}\d{1,100})""",
      """"Computer":"({host}[^"]+)""",
      """<Data Name='Status'>({result_code}[^<]+)</Data>""",
      """<Data Name='ServiceName'>({dest_host}[^<]+\$)</Data>""",
      """<Data Name='ServiceName'>({service_name}[^<]+)</Data>""",
      """<Data Name='TicketOptions'>({ticket_options}[^<]+)</Data>""",
      """<Data Name='TicketEncryptionType'>({ticket_encryption_type}[^<]+)</Data>""",
      """<Data Name='TargetUserName'>(?=\w)({user}[^<]+)</Data>""",
      """<Data Name='TargetDomainName'>(?=\w)({domain}[^<]+)</Data>""",
      """<Data Name='IpAddress'>(::[\w]+:)?({src_ip}[a-fA-F:\d.]+)"""
    ]
  }
```