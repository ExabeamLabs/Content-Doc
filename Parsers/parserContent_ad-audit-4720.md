#### Parser Content
```Java
{
Name = ad-audit-4720
  Vendor = AD Audit
  Product = AD Audit
  Lms = Direct
  DataType = "windows-account-created"
  TimeFormat = "epoch_sec"
  Conditions = [ """ADAuditPlus""", """EVENT_NUMBER = 4720""", """A user account was created""" ]
  Fields = [
    """TIME_GENERATED\s*=\s*({time}\d+)""",
    """({host}[\w\-.]+) ADAuditPlus""",
    """CALLER_USER_NAME\s*=\s*({user}[^\s\]]+)""",
    """CALLER_USER_DOMAIN\s*=\s*({domain}[^\s\]]+)""",
    """SOURCE\s*=\s*({src_host}[\w\-.]+)""",
    """RECORD_NUMBER\s*=\s*({record_id}\d+)""",
    """EVENT_NUMBER\s*=\s*({event_code}\d+)""",
    """CALLER_USER_SID\s*=\s*({user_sid}[^\s]+)""",
    """CALLER_LOGON_ID\s*=\s*({logon_id}[^\s]+)""",
    """ACCOUNT_NAME\s*=\s*({account_name}[^\s]+)""",
    """ACCOUNT_DOMAIN\s*=\s*({account_domain}[^\s]+)""",
    """ACCOUNT_SID\s*=\s*\%\{({account_id}[^\s\}]+)""",
  ]
}
```