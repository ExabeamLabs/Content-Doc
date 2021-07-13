#### Parser Content
```Java
{
Name = raw-4648-5
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-account-switch"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """Microsoft-Windows-Security-Auditing""","""SubjectUserName:""", """TargetUserName:""", """4648""", """TargetServerName:""", """Logon""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)\.\d{1,3}[+\-]{1,20}\d\d:\d\d""",
    """({outcome}(Success|Failure) Audit)\s{1,100}({host}[^\s]{1,2000})\s{1,100}Logon""",
    """({event_code}4648)""",
    """SubjectUserName:(-|({user}[^,]{1,2000})),""",
    """SubjectDomainName:(-|({domain}[^,]{1,2000})),""",
    """SubjectLogonId:({logon_id}[^,]{1,2000}),""",
    """SubjectUserSid:({user_sid}[^,]{1,2000}),""",
    """TargetUserName:({account}[^,]{1,2000}),""",
    """TargetDomainName:({account_domain}[^,]{1,2000}),""",
    """TargetServerName:({dest_host}[^,]{1,2000}),""",
    """TargetInfo:({dest_service}[^,]{1,2000}),""",
    """TargetLogonGuid:({account_logon_guid}[^,]{1,2000}),""",
    """\sLogonGuid:({user_logon_guid}[^,]{1,2000}),""",
    """ProcessId:({pid}[^,]{1,2000}),""",
    """ProcessName:({process}({directory}([^,]{1,2000})[\\\/])?({process_name}[^,\\]{1,2000}?)),\s{1,100}\w+:""",
    """IpAddress:(::ffff:)?({src_ip}[a-fA-F\d:.]{1,2000}),""",
    """IpPort:({src_port}\d{1,100}),"""
  ]
}
```