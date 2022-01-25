#### Parser Content
```Java
{
Name = centrify-authentication-success-1
  Vendor = Centrify
  Product = Centrify Authentication Service
  Lms = Splunk
  DataType = "authentication-successful"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ """SourceName=Centrify AuditTrail""", """AUDIT_TRAIL|Centrify Suite|MFA|""" , """|MFA challenge succeeded|""", """EventCode=54206""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """:\d\d\s\w+\s({time}\d\d\/\d\d\/\d\d\d\d\s\d\d:\d\d:\d\d\s(?i)(AM|PM))""",
    """entityname=({domain}[^\\]{1,2000})\\({dest_host}[^\s]{1,2000})""",
    """User=(NULL|NOT_TRANSLATED|({user}[^\s]{1,2000}))""",
    """Sid=({user_sid}[^\s]{1,2000}?)\sSidType""",
    """EventCode=({event_code}54206)""",
    """AUDIT_TRAIL\|Centrify Suite\|MFA\|[^=]{1,2000}({event_name}MFA challenge succeeded)""",
    """Message:\s{0,100}({additional_info}[^:]{1,2000})\.\s{1,100}""",
  ]
}
```