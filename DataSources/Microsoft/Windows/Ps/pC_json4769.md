#### Parser Content
```Java
{
Name = json-4769
    Vendor = Microsoft
    Product = Windows
    Lms = Direct
    DataType = "windows-4769"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = ["""4769""", """"TransmittedServices":""""]
    Fields = [
      """({event_name}A Kerberos service ticket was requested)""",
      """"EventTime":"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """"EventReceivedTime":\s{0,100}({time}\d{1,100})""",
      """"timestamp":\s{0,100}({time}\d{1,100})""",
      """\s({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\dZ)\s[^\s]{1,2000}\s""",
      """"{1,20}created"{1,20}:"{1,20}({time}[^"]{1,2000})""",
      """"TimeCreated"{1,20}:"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """"Computer"{1,20}:"{1,20}({host}[^"]{1,2000})""""
      """"{1,20}(?:winlog\.)?computer_name"{1,20}:"{1,20}({host}[^"]{1,2000})""",
      """"(Hostname|MachineName)":"({host}[^"]{0,2000})""",
      """({event_code}4769)""",
      """"TargetUserName":"({user}[^@"]{1,2000})""",
      """"TargetDomainName":"({domain}[^."]{1,2000})""",
      """"ServiceName":"({dest_host}[^@"]{1,2000}\$)"""",
      """"ServiceName":"({service_name}[^@"]{1,2000})"""",
      """"TicketOptions":"({ticket_options}[^"]{1,2000})""",
      """"TicketEncryptionType":"({ticket_encryption_type}[^"]{1,2000})""",
      """"IpAddress":"(::[\w]{1,2000}:)?({src_ip}[a-fA-F:\d.]{1,2000})""",
      """"Status":"({result_code}[^"]{1,2000})"""
    ]
  

}
```