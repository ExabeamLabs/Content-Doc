#### Parser Content
```Java
{
Name = syslog-json-4720
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-account-created"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """"EventID":4720""",""""SourceModuleType":""" ]
  Fields = [ 
    """({event_name}A user account was created)""",
	      """"EventTime":\s{0,100}"({time}\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"""",
              """"Hostname":"({host}[^."]*)""",
              """({event_code}4720)""",
	      """"SubjectUserName":"({user}[^"]+)""",
	      """"SubjectDomainName":"({domain}[^"]+)""",
	      """"SubjectLogonId":"({logon_id}[^"]+)""",
	      """"TargetSid":"({account_id}[^"]+)""",
	      """"TargetUserName":"({account_name}[^"]+)""",
	      """"TargetDomainName":"({account_domain}[^"]+)"""
	]
    DupFields = ["host->dest_host"]
}
```