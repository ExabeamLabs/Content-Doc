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
    """"Hostname"+:"+({host}[^"]+)""",
    """"EventReceivedTime"+:"+({time}[^"]+)"""
    """"EventType"+:"+({outcome}[^"]+)""",
    """({event_code}4768)""",
    """"ProcessID"+:({process_id}\d+)""",
    """"Category"+:"+({event_name}[^"]+)""",
    """"TargetUserName"+:"+({user}[^"]+)""",
    """"TargetDomainName"+:"+({domain}[^"]+)"""",
    """TargetSid"+:"+({user_sid}[^"]+)"""",
    """IpAddress"+:"+(::[\w]+:)?({dest_ip}[a-fA-F:\d.]+)""",
    """"ServiceName"+:"+({service_name}[^"]+)""",
    """"TicketOptions"+:"+({ticket_options}[^"]+)""",
    """"Status"+:"+({result_code}[^"]+)""",
    """"IpPort"+:"+({dest_port}\d+)""",
  ]
     DupFields = [ "host->dest_host" ]
}
```