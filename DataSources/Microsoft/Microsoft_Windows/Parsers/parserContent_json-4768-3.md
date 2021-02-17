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
    """"TimeCreated"+:"+({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"Computer"+:"+({host}[^"]+)"""",
    """"TicketOptions":"({ticket_options}[^"]+)""",
    """"TicketEncryptionType":"({ticket_encryption_type}[^"]+)""",
    """"ServiceName":"({service_name}[^"]+)""",
    """"Status":"({result_code}[^"]+)""",
    """"IpAddress":"({dest_ip}[a-fA-F.:\d]+)""",
    """TargetUserName":"(?:-|(?i)(system|anonymous logon|LOCAL SERVICE|LOCAL SYSTEM)|({user}[^"]+))"""",
    """TargetDomainNam":"(?:-|({domain}[^"]+?))"""",
    """TargetSid":"({user_sid}[^"\\]+)""""
  ]
}
```