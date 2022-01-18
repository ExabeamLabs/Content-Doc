#### Parser Content
```Java
{
Name = s-xml-windows-member-14
  DataType = "vpn-end"
  Conditions = [ """<EventID>4304</EventID>""", """<EventRecordID>""" ]
  Fields =${WinParserTemplates.s-xml-windows-member.Fields}[
    """'RemoteIP'>({src_translated_ip}[A-Fa-f:\d.]{1,2000})""",
    """'TunnelSourceIP'>({src_ip}[A-Fa-f:\d.]{1,2000})""", 
  ]


s-xml-windows-member = {
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Fields = [
    """SystemTime(\\)?=\'({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """<EventID>({event_code}[^<]{1,2000})</EventID>""",
    """<Computer>({host}[^<]{1,2000})</Computer>""",
    """<Data Name(\\)?='MemberName'>({account_dn}(?i)(cn)=.+?,({account_ou}OU.+?DC=[\w-]{1,2000}))</Data>""",
    """<Data Name(\\)?='MemberSid'>({account_id}(?=[^\\<]{1,2000}\\)({sid_domain}[^\\]{1,2000})\\({sid_user}[^\s]{1,2000})|(?:[^\s\<]{1,2000}))</Data>""",
    """<Data Name(\\)?='TargetUserName'>(?=\w)({group_name}[^<]{1,2000})</Data>""",
    """<Data Name(\\)?='TargetDomainName'>(?=\w)({group_domain}[^<]{1,2000})</Data>""",
    """<Data Name(\\)?='TargetSid'>({group_id}[^<]{1,2000})</Data>""",
    """<Data Name(\\)?='SubjectUserSid'>({user_sid}[^<]{1,2000})</Data>""",
    """<Data Name(\\)?='SubjectUserName'>({user}[^<]{1,2000})</Data>""",
    """<Data Name(\\)?='SubjectDomainName'>({domain}[^<]{1,2000})</Data>""",
    """<Data Name(\\)?='SubjectLogonId'>({logon_id}[^<]{1,2000})</Data>""",
    """<Data Name(\\)?='RemoteIPAddress'>({dest_ip}[^<]{1,2000})""",
    """<Data Name(\\)?='LocalIPAddress'>({src_ip}[a-fA-F:\d.]{1,2000})<""",
    """<Data Name(\\)?='RemotePort'>({dest_port}[^<]{1,2000})""",
    """<Data Name(\\)?='LocalPort'>({src_port}[^<]{1,2000})""",
    """<Message>({additional_info}[^<]{1,2000})""",
    """<Provider>({provider_name}[^<]{1,2000})""",
    """<System>.*?Guid(\\)?='\{({process_guid}[^}]{1,2000})""",
    """<Execution ProcessID(\\)?='({proccess_id}\d{1,100})""",
    """<Security UserID(\\)?='({user_sid}[^']{1,2000})""",
    """<Data Name(\\)?='RemoteMachineAccount'>({dest_host}[^<]{1,2000})"""
    
  ]
  DupFields = [ "host->dest_host" 
}
```