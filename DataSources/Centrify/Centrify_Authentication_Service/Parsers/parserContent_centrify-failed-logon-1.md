#### Parser Content
```Java
{
Name = centrify-failed-logon-1
  Vendor = Centrify
  Product = Centrify Authentication Service
  Lms = Splunk
  DataType = "failed-logon"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ """SourceName=Centrify AuditTrail""", """AUDIT_TRAIL|Centrify Suite|DirectAuthorize - Windows|""" , """|Remote login failure|""", """EventCode=6034""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """:\d\d\s\w+\s({time}\d\d\/\d\d\/\d\d\d\d\s\d\d:\d\d:\d\d\s(?i)(AM|PM))""",
    """entityname=({domain}[^\\]{1,2000})\\({dest_host}[^\s]{1,2000})""",
    """User=(NULL|NOT_TRANSLATED|({user}[^\s]{1,2000}))""",
    """Sid=({user_sid}[^\s]{1,2000}?)\sSidType""",
    """EventCode=({event_code}6034)""",
    """AUDIT_TRAIL\|Centrify Suite\|DirectAuthorize - Windows[^=]{1,2000}?({event_name}Remote login failure)""",
    """reason=({failure_reason}[^=]{1,2000})\.(\s{1,100}\w+=)?""",
    """Message:\s{0,100}({additional_info}[^:]{1,2000})\.\s{1,100}""",
  ]
}
```