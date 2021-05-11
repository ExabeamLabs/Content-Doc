#### Parser Content
```Java
{
Name = syslog-json-4722
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-account-enabled"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """"EventID":4722""",""""SourceModuleType":""" ]
  Fields = [ 
    """({event_name}A user account was enabled)""",
	      """"EventTime":\s{0,100}"({time}\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"""",
              """"Hostname":"({host}[^."]*)""",
              """({event_code}4722)""",
	      """"RecordNumber":({record_id}[^,]+)""",
	      """"SubjectUserName":"({user}[^"]+)""",
	      """"SubjectDomainName":"({domain}[^"]+)""",
	      """"SubjectLogonId":"({logon_id}[^"]+)""",
	      """"TargetUserName":"({target_user}[^"]+)""",
	      """"TargetDomainName":"({target_domain}[^"]+)"""
	]
}
```