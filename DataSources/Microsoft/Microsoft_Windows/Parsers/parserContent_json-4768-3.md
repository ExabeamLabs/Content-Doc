#### Parser Content
```Java
{
Name = json-4768-3
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-4768"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """"EventID":"4768"""", """A Kerberos authentication ticket (TGT) was requested""" ]
  Fields =[
    """({event_name}A Kerberos authentication ticket \(TGT\) was requested)""",
    """({event_code}4768)""",
    """"TimeCreated"{1,20}:"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"Computer"{1,20}:"{1,20}({host}[^"]{1,2000})"""",
    """"TicketOptions":"({ticket_options}[^"]{1,2000})""",
    """"TicketEncryptionType":"({ticket_encryption_type}[^"]{1,2000})""",
    """"ServiceName":"({service_name}[^"]{1,2000})""",
    """"Status":"({result_code}[^"]{1,2000})""",
    """"IpAddress":"({dest_ip}[a-fA-F.:\d]{1,2000})""",
    """TargetUserName":"(?:-|(?i)(system|anonymous logon|LOCAL SERVICE|LOCAL SYSTEM)|({user}[^"]{1,2000}))"""",
    """TargetDomainNam":"(?:-|({domain}[^"]{1,2000}?))"""",
    """TargetSid":"({user_sid}[^"\\]{1,2000})""""
  ]
}
```