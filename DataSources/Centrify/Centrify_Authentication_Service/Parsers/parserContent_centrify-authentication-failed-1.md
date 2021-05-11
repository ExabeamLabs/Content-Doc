#### Parser Content
```Java
{
Name = centrify-authentication-failed-1
  Vendor = Centrify
  Product = Centrify Authentication Service
  Lms = Splunk
  DataType = "authentication-failed"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ """SourceName=Centrify AuditTrail""", """AUDIT_TRAIL|Centrify Suite|MFA|""" , """|MFA challenge failed|""", """EventCode=54207""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """:\d\d\s\w+\s({time}\d\d\/\d\d\/\d\d\d\d\s\d\d:\d\d:\d\d\s(?i)(AM|PM))""",
    """entityname=({domain}[^\\]+)\\({dest_host}[^\s]+)""",
    """User=(NULL|NOT_TRANSLATED|({user}[^\s]+))""",
    """Sid=({user_sid}[^\s]+?)\sSidType""",
    """EventCode=({event_code}54207)""",
    """AUDIT_TRAIL\|Centrify Suite\|MFA\|[^=]+({event_name}MFA challenge failed)""",
    """reason=({failure_reason}[^=]+)\.\s+""",
    """Message:\s*({additional_info}[^:]+)\.\s+""",
  ]
}
```