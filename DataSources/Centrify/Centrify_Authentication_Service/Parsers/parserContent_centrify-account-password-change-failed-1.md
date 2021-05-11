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
    """exabeam_host=({host}[\w.\-]+)""",
    """:\d\d\s\w+\s({time}\d\d\/\d\d\/\d\d\d\d\s\d\d:\d\d:\d\d\s(?i)(AM|PM))""",
    """ComputerName=({dest_host}[^\.]+)\.({domain}[^\s]+)""",
    """User=(NULL|NOT_TRANSLATED|({user}[^\s]+))""",
    """Sid=({user_sid}[^\s]+?)\sSidType""",
    """EventCode=({event_code}6041)""",
    """AUDIT_TRAIL\|Centrify Suite\|DirectAuthorize - Windows[^=]+({event_name}Self-service password reset failure)""",
    """reason=({failure_reason}[^=]+)\.?"""",
    """Message:\s*({additional_info}[^:]+)\.\s+""",
  ]
}
```