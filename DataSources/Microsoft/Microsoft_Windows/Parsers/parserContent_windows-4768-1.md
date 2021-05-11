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
    """"Hostname"{1,20}:"{1,20}({host}[^"]+)""",
    """"EventReceivedTime"{1,20}:"{1,20}({time}[^"]+)"""
    """"EventType"{1,20}:"{1,20}({outcome}[^"]+)""",
    """({event_code}4768)""",
    """"ProcessID"{1,20}:({process_id}\d{1,100})""",
    """"Category"{1,20}:"{1,20}({event_name}[^"]+)""",
    """"TargetUserName"{1,20}:"{1,20}({user}[^"]+)""",
    """"TargetDomainName"{1,20}:"{1,20}({domain}[^"]+)"""",
    """TargetSid"{1,20}:"{1,20}({user_sid}[^"]+)"""",
    """IpAddress"{1,20}:"{1,20}(::[\w]+:)?({dest_ip}[a-fA-F:\d.]+)""",
    """"ServiceName"{1,20}:"{1,20}({service_name}[^"]+)""",
    """"TicketOptions"{1,20}:"{1,20}({ticket_options}[^"]+)""",
    """"Status"{1,20}:"{1,20}({result_code}[^"]+)""",
    """"IpPort"{1,20}:"{1,20}({dest_port}\d{1,100})""",
    """"TicketEncryptionType":"({ticket_encryption_type}[^"]+)""",
  ]
     DupFields = [ "host->dest_host" ]
}
```