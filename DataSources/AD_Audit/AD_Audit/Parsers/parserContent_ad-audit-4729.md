#### Parser Content
```Java
{
Name = ad-audit-4729
  Vendor = AD Audit
  Product = AD Audit
  Lms = Direct
  DataType = "windows-member-removed"
  TimeFormat = "epoch_sec"
  Conditions = [ """ADAuditPlus""", """EVENT_NUMBER = """, """ was removed from """ ]
  Fields = [
    """TIME_GENERATED\s*=\s*({time}\d+)""",
    """({host}[\w\-.]+) ADAuditPlus""",
    """CALLER_USER_NAME\s*=\s*({user}[^\s\]]+)""",
    """CALLER_USER_DOMAIN\s*=\s*({domain}[^\s\]]+)""",
    """SOURCE\s*=\s*({src_host}[\w\-.]+)""",
    """EVENT_NUMBER\s*=\s*({event_code}\d+)""",
    """CALLER_LOGON_ID\s*=\s*({logon_id}[^\s]+)""",
    """ACCOUNT_SID\s*=\s*\%\{({account_id}[^\s\}]+)""",
    """GROUP_TYPE\s*=\s*({group_type}[^\]]+?)\s*\]""",
    """was removed from .+? Group '({group_name}[^']+)""",
    """MEMBER_NAME\s*=\s*(?:-|({account_dn}CN=.+?,({account_ou}OU.+?DC=[\w-]+)))""",
  ]
  DupFields=[ "host->dest_host" ]
}
```