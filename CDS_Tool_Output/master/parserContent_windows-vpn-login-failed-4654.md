#### Parser Content
```Java
{
Name = windows-vpn-login-failed-4654
  DataType = "failed-vpn-login"
  Conditions = [ """(4654)""", """[WIN]""", """Microsoft-Windows-Security-Auditing""" ]
  Fields = ${WinParserTemplates.windows-vpn-direct-access.Fields} [
    """({event_name}An IPsec quick mode negotiation failed)"""
    """({outcome}failed)""",
  ]
}

${WinParserTemplates.windows-vpn-direct-access} {
  Name = windows-vpn-login-4981
  DataType = "vpn-login"
  Conditions = [ """(4981)""", """[WIN]""", """Microsoft-Windows-Security-Auditing""" ]
  Fields = ${WinParserTemplates.windows-vpn-direct-access.Fields} [
    """({event_name}IPsec main mode and extended mode security associations were established)""",
    """Remote Endpoint: Principal Name:\s*(\w+(\\+|\/+))?({dest_host}[^\s]+)\s""",
    """Remote Principal Name:\s*(({domain}[^\\]+)\\)?({user}[^\s]+)\s""",
  ]
}

${WinParserTemplates.windows-vpn-direct-access} {
  Name = windows-vpn-login-4979
  DataType = "vpn-login"
  Conditions = [ """(4979)""", """[WIN]""", """Microsoft-Windows-Security-Auditing""" ]
  Fields = ${WinParserTemplates.windows-vpn-direct-access.Fields} [
    """({event_name}IPsec main mode and extended mode security associations were established)""",
    """Remote Endpoint: Principal Name:\s*(\w+(\\+|\/+))?({dest_host}[^\s]+)\s""",
    """Remote Principal Name:\s*(({domain}[^\\]+)\\)?({user}[^\s]+)\s""",
  ]
}
{
  Name = xml-4622
  Vendor = Microsoft Windows
  Lms = Syslog
  DataType = "service-created"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """<EventID>4622<""", """<Provider Name='Microsoft-Windows-Security-Auditing'""", """A security package has been loaded by the Local Security Authority""" ]
  Fields = [
    """<EventID>({event_code}\d+)""",
    """<TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """<Computer>({host}[^<]+)""",
    """<Keyword>({outcome}[^<]+)<\/Keyword>""",
    """<EventRecordID>({record_id}[^<]+)<\/EventRecordID>""",
    """<Message>({event_name}[^<]+)<\/Message>""",
    """Message>.*?<Task>({activity}.*?)<\/Task>""",
    """<Provider Name='Microsoft-Windows-Security-Auditing' Guid='\{({process_guid}[^}]+?)\}""",
    """<Correlation ActivityID='\{({activity_id}[^\}']+)""",
    """<Execution ProcessID='({process_id}[^']+)""",
    """ThreadID='({thread_id}[^']+)""",
    """<Provider>({provider_name}.+?)<\/Provider>""",
    """<Data Name='SecurityPackageName'>({service_name}[^<]+)<""",
  ]
  DupFields = ["host->dest_host"]
}

{
  Name = xml-5478
  Vendor = Microsoft Windows
  Lms = Syslog
  DataType = "service-created"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """<EventID>5478<""", """<Provider Name='Microsoft-Windows-Security-Auditing'""", """The IPsec Policy Agent service was started""" ]
  Fields = [
    """<EventID>({event_code}\d+)""",
    """<TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """<Computer>({host}[^<]+)""",
    """<Keyword>({outcome}[^<]+)<\/Keyword>""",
    """<EventRecordID>({record_id}[^<]+)<\/EventRecordID>""",
    """<Message>({event_name}[^<]+)<\/Message>""",
    """Message>.*?<Task>({activity}.*?)<\/Task>""",
    """<Provider Name='Microsoft-Windows-Security-Auditing' Guid='\{({process_guid}[^}]+?)\}""",
    """<Correlation ActivityID='\{({activity_id}[^\}']+)""",
    """<Execution ProcessID='({process_id}[^']+)""",
    """ThreadID='({thread_id}[^']+)""",
    """<Provider>({provider_name}.+?)<\/Provider>""",
    """({service_name}IPsec Policy Agent)"""
  ]
  DupFields = ["host->dest_host"]
}

  {
    Name = raw-8004-1
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-failed-logon"
    TimeFormat = "MM/dd/yyyy HH:mm:ss"
    Conditions = [ """security policy Network Security:""", """Restrict NTLM:""", """EventCode=8004""" ]
    Fields = [
      """({event_name}Domain Controller Blocked Audit: Audit NTLM authentication to this domain controller)""",
      """({time}\d\d/\d\d/\d\d\d\d \d\d:\d\d:\d\d)""",
      """ComputerName=({host}[^\s]+)""",
      """({event_code}8004)""",
      """User name:\s+({user}[^\s]+)""",
      """Domain name:\s+(NULL|({domain}[^\s]+))""",
      """RecordNumber=({record_id}\d+)""",
      """Channel name:\s*({resource}.*?)\s+User name:""",
      """Workstation name:\s*\\?(NULL|({src_host}[\w\-.]+))\s+Secure Channel type:""",
      """security policy Network Security:\s*Restrict NTLM:\s*({policy}[^\.]+)""",
    ]
    DupFields = ["host->dest_host"]
  }
```