#### Parser Content
```Java
{
Name = windows-4768-1
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = ArcSight
  DataType = "windows-4768"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """EventID":4768""", """EventType""", """Kerberos Authentication Service""" ]
  Fields = [
    """"Hostname"{1,20}:"{1,20}({host}[^"]{1,2000})""",
    """"EventReceivedTime"{1,20}:"{1,20}({time}[^"]{1,2000})"""
    """"EventType"{1,20}:"{1,20}({outcome}[^"]{1,2000})""",
    """({event_code}4768)""",
    """"ProcessID"{1,20}:({process_id}\d{1,100})""",
    """"Category"{1,20}:"{1,20}({event_name}[^"]{1,2000})""",
    """"TargetUserName"{1,20}:"{1,20}({user}[^"]{1,2000})""",
    """"TargetDomainName"{1,20}:"{1,20}({domain}[^"]{1,2000})"""",
    """TargetSid"{1,20}:"{1,20}({user_sid}[^"]{1,2000})"""",
    """IpAddress"{1,20}:"{1,20}(::[\w]{1,2000}:)?({dest_ip}[a-fA-F:\d.]{1,2000})""",
    """"ServiceName"{1,20}:"{1,20}({service_name}[^"]{1,2000})""",
    """"TicketOptions"{1,20}:"{1,20}({ticket_options}[^"]{1,2000})""",
    """"Status"{1,20}:"{1,20}({result_code}[^"]{1,2000})""",
    """"IpPort"{1,20}:"{1,20}({dest_port}\d{1,100})""",
    """"TicketEncryptionType":"({ticket_encryption_type}[^"]{1,2000})""",
  ]
     DupFields = [ "host->dest_host" ]
}
```