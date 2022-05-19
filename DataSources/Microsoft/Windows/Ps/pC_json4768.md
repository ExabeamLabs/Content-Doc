#### Parser Content
```Java
{
Name = json-4768
    Vendor = Microsoft
    Product = Windows
    Lms = Direct
    DataType = "windows-4768"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Conditions = [""":4768""", """"ServiceName":"""", """Pre-Authentication"""]
    Fields = [
      """({event_name}A Kerberos authentication ticket \(TGT\) was requested)""",
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """"EventTime":"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """"EventReceivedTime":\s{0,100}({time}\d{1,100})""",
      """"timestamp":\s{0,100}({time}\d{1,100})""",
      """\s({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\dZ)\s[^\s]{1,2000}\s""",
      """"time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\dZ)"""",
      """"(Hostname|MachineName|(?:winlog\.)?computer_name)":"({host}[^"]{0,2000})""",
      """({event_code}4768)""",
      """"(TargetUserName|AccountName)":"({user}[^"]{1,2000})""",
      """"(TargetDomainName|SuppliedRealmName)":"({domain}[^."]{1,2000})""",
      """"(UserID|TargetSid)":"({user_sid}[^"]{1,2000})""",
      """"(IpAddress|ClientAddress)":"(::[\w]{1,2000}:)?({dest_ip}[a-fA-F:\d.]{1,2000})""",
      """"(Status|ResultCode)":"({result_code}[^"]{1,2000})""",
      """"TicketOptions":"({ticket_options}[^"]{1,2000})""",
      """"TicketEncryptionType":"({ticket_encryption_type}[^"]{1,2000})""",
      """"ServiceName":"({service_name}[^"]{1,2000})""",
    ]
  

}
```