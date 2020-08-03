#### Parser Content
```Java
{
Name = xml-1310
 Vendor = Microsoft
 Product = Microsoft Windows
 Lms = Direct
 DataType = "failed-logon"
 TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSSZ"
 Conditions = [ """<EventID Qualifiers='16640'>1310<""", """Failed NTLM Authentication"""]
 Fields = [
   """<Provider Name='({provider_name}[^']+)""",
   """<EventID Qualifiers='16640'>({event_code}[^<]+)""",
   """<Keywords>({outcome}[^<]+)""",
   """<TimeCreated SystemTime='({time}.+?)'""",
   """<EventRecordID>({record_id}[^<]+)""",
   """<Computer>({host}[^<]+)""",
   """status=([^:]+:)({result_code}[^:]+):"""
   """Failed NTLM Authentication for user:\s+'({domain}[^\\]+)\\({user}[^']+)""",
   """<Message>({event_name}.+?)\s*<"""
   """status=([^:]+:){2}({failure_reason}.+?)\s<"""
   ]
   DupFields = ["host->dest_host"]
}

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