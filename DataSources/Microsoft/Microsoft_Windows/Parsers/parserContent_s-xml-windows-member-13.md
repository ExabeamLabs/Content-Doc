#### Parser Content
```Java
{
Name = s-xml-windows-member-13
  DataType = "vpn-start"
  Conditions = [ """<EventID>4303</EventID>""" ,"""<EventRecordID>""" ]
   Fields =${WinParserTemplates.s-xml-windows-member.Fields}[
    """'ClientMachineName'>(Unknown|({src_host}[\w\-.]+))""",
    """'RemoteIP'>({src_translated_ip}[A-Fa-f:\d.]+)""",
    """'TunnelSourceIP'>({src_ip}[A-Fa-f:\d.]+)""",

  ]
}
s-xml-windows-member = {
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Fields = [
    """SystemTime(\\)?=\'({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """<EventID>({event_code}[^<]+)</EventID>""",
    """<Computer>({host}[^<]+)</Computer>""",
    """<Data Name(\\)?='MemberName'>({account_dn}(?i)(cn)=.+?,({account_ou}OU.+?DC=[\w-]+))</Data>""",
    """<Data Name(\\)?='MemberSid'>({account_id}(?=[^\\<]+\\)({sid_domain}[^\\]+)\\({sid_user}[^\s]+)|(?:[^\s\<]+))</Data>""",
    """<Data Name(\\)?='TargetUserName'>(?=\w)({group_name}[^<]+)</Data>""",
    """<Data Name(\\)?='TargetDomainName'>(?=\w)({group_domain}[^<]+)</Data>""",
    """<Data Name(\\)?='TargetSid'>({group_id}[^<]+)</Data>""",
    """<Data Name(\\)?='SubjectUserSid'>({user_sid}[^<]+)</Data>""",
    """<Data Name(\\)?='SubjectUserName'>({user}[^<]+)</Data>""",
    """<Data Name(\\)?='SubjectDomainName'>({domain}[^<]+)</Data>""",
    """<Data Name(\\)?='SubjectLogonId'>({logon_id}[^<]+)</Data>""",
    """<Data Name(\\)?='RemoteIPAddress'>({dest_ip}[^<]+)""",
    """<Data Name(\\)?='LocalIPAddress'>({src_ip}[^<]+)""",
    """<Data Name(\\)?='RemotePort'>({dest_port}[^<]+)""",
    """<Data Name(\\)?='LocalPort'>({src_port}[^<]+)""",
    """<Message>({additional_info}[^<]+)""",
    """<Provider>({provider_name}[^<]+)""",
    """<System>.*?Guid(\\)?='\{({process_guid}[^}]+)""",
    """<Execution ProcessID(\\)?='({proccess_id}\d{1,100})""",
    """<Security UserID(\\)?='({user_sid}[^']+)""",
    """<Data Name(\\)?='RemoteMachineAccount'>({dest_host}[^<]+)"""
    
  ]

```