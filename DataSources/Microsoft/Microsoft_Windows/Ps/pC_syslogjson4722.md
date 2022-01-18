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
              """"Hostname":"({host}[^."]{0,2000})""",
              """({event_code}4722)""",
	      """"RecordNumber":({record_id}[^,]{1,2000})""",
	      """"SubjectUserName":"({user}[^"]{1,2000})""",
	      """"SubjectDomainName":"({domain}[^"]{1,2000})""",
	      """"SubjectLogonId":"({logon_id}[^"]{1,2000})""",
	      """"TargetUserName":"({target_user}[^"]{1,2000})""",
	      """"TargetDomainName":"({target_domain}[^"]{1,2000})"""
	]


}
```