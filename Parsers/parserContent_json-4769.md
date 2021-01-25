#### Parser Content
```Java
{
Name = json-4769
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-4769"
    TimeFormat = "epoch_sec"
    Conditions = ["""4769""", """"TransmittedServices":""""]
    Fields = [
      """({event_name}A Kerberos service ticket was requested)""",
      """"EventTime":"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """"EventReceivedTime":\s*({time}\d+)""",
      """"timestamp":\s*({time}\d+)""",
      """"(Hostname|MachineName)":"({host}[^"]*)""",
      """({event_code}4769)""",
      """"TargetUserName":"({user}[^@"]+)""",
      """"TargetDomainName":"({domain}[^."]+)""",
      """"ServiceName":"({dest_host}[^@"]+\$)"""",
      """"ServiceName":"({service_name}[^@"]+)"""",
      """"TicketOptions":"({ticket_options}[^"]+)""",
      """"TicketEncryptionType":"({ticket_encryption_type}[^"]+)""",
      """"IpAddress":"(::[\w]+:)?({src_ip}[a-fA-F:\d.]+)""",
      """"Status":"({result_code}[^"]+)"""
    ]
  }
```