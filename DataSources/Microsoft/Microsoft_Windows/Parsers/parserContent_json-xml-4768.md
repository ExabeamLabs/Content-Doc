#### Parser Content
```Java
{
Name = json-xml-4768
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-4768"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = [ """"EventID":"4768"""", """<Data Name='""" ]
    Fields = [
      """"TimeGenerated":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """"Computer":"({host}[^"]+)""",
      """"EventID":"({event_code}\d+)""",
      """<Data Name='TargetSid'>({user_sid}[^<]+)</Data>""",
      """<Data Name='Status'>({result_code}[^<]+)</Data>""",
      """<Data Name='TargetUserName'>(?=\w)({user}[^<]+)</Data>""",
      """<Data Name='TargetDomainName'>(?=\w)({domain}[^<]+)</Data>""",
      """<Data Name='IpAddress'>(::[\w]+:)?({dest_ip}[a-fA-F:\d.]+)""",
      """<Data Name='TicketEncryptionType'>({ticket_encryption_type}[^<]+)</Data>""",
      """<Data Name='TicketOptions'>({ticket_options}[^<]+)</Data>""",
      """<Data Name='ServiceName'>({service_name}[^<]+)</Data>""",
    ]
  }
```