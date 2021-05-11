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
    """exabeam_host=({host}[\w.\-]+)""",
    """:\d\d\s\w+\s({time}\d\d\/\d\d\/\d\d\d\d\s\d\d:\d\d:\d\d\s(?i)(AM|PM))""",
    """entityname=({domain}[^\\]+)\\({dest_host}[^\s]+)""",
    """User=(NULL|NOT_TRANSLATED|({user}[^\s]+))""",
    """Sid=({user_sid}[^\s]+?)\sSidType""",
    """EventCode=({event_code}54206)""",
    """AUDIT_TRAIL\|Centrify Suite\|MFA\|[^=]+({event_name}MFA challenge succeeded)""",
    """Message:\s*({additional_info}[^:]+)\.\s+""",
  ]
}
```