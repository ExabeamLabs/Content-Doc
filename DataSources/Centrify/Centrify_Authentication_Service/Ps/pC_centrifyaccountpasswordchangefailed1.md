#### Parser Content
```Java
{
Name = centrify-account-password-change-failed-1
  Vendor = Centrify
  Product = Centrify Authentication Service
  Lms = Splunk
  DataType = "account-password-reset"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ """SourceName=Centrify AuditTrail""", """AUDIT_TRAIL|Centrify Suite|DirectAuthorize - Windows|""" , """|Self-service password reset failure|""", """EventCode=6041""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """:\d\d\s\w+\s({time}\d\d\/\d\d\/\d\d\d\d\s\d\d:\d\d:\d\d\s(?i)(AM|PM))""",
    """ComputerName=({dest_host}[^\.]{1,2000})\.({domain}[^\s]{1,2000})""",
    """User=(NULL|NOT_TRANSLATED|({user}[^\s]{1,2000}))""",
    """Sid=({user_sid}[^\s]{1,2000}?)\sSidType""",
    """EventCode=({event_code}6041)""",
    """AUDIT_TRAIL\|Centrify Suite\|DirectAuthorize - Windows[^=]{1,2000}({event_name}Self-service password reset failure)""",
    """reason=({failure_reason}[^=]{1,2000})\.?"""",
    """Message:\s{0,100}({additional_info}[^:]{1,2000})\.\s{1,100}""",
  ]
}
```