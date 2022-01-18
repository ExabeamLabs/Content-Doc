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
              """"Hostname":"({host}[^."]{0,2000})""",
              """({event_code}4720)""",
	      """"SubjectUserName":"({user}[^"]{1,2000})""",
	      """"SubjectDomainName":"({domain}[^"]{1,2000})""",
	      """"SubjectLogonId":"({logon_id}[^"]{1,2000})""",
	      """"TargetSid":"({account_id}[^"]{1,2000})""",
	      """"TargetUserName":"({account_name}[^"]{1,2000})""",
	      """"TargetDomainName":"({account_domain}[^"]{1,2000})"""
	]
    DupFields = ["host->dest_host"]


}
```