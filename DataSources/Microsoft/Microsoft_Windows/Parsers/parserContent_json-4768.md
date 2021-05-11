#### Parser Content
```Java
{
Name = json-4768
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-4768"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Conditions = [""":4768""", """"ServiceName":"""", """Pre-Authentication"""]
    Fields = [
      """({event_name}A Kerberos authentication ticket \(TGT\) was requested)""",
      """"EventTime":"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """"EventReceivedTime":\s{0,100}({time}\d{1,100})""",
      """"timestamp":\s{0,100}({time}\d{1,100})""",
      """\s({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\dZ)\s[^\s]+\sSkyformation""",
      """"time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\dZ)"""",
      """"(Hostname|MachineName|(?:winlog\.)?computer_name)":"({host}[^"]*)""",
      """({event_code}4768)""",
      """"(TargetUserName|AccountName)":"({user}[^"]+)""",
      """"(TargetDomainName|SuppliedRealmName)":"({domain}[^."]+)""",
      """"(UserID|TargetSid)":"({user_sid}[^"]+)""",
      """"(IpAddress|ClientAddress)":"(::[\w]+:)?({dest_ip}[a-fA-F:\d.]+)""",
      """"(Status|ResultCode)":"({result_code}[^"]+)""",
      """"TicketOptions":"({ticket_options}[^"]+)""",
      """"TicketEncryptionType":"({ticket_encryption_type}[^"]+)""",
      """"ServiceName":"({service_name}[^"]+)""",
    ]
  }
```