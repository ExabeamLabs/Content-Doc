#### Parser Content
```Java
{
Name = ad-audit-4728
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-member-added"
  TimeFormat = "epoch_sec"
  Conditions = [ """ADAuditPlus""", """EVENT_NUMBER = """, """REMARKS = A member was added to """ ]
  Fields = [
    """TIME_GENERATED\s{0,100}=\s{0,100}({time}\d{1,100})""",
    """({host}[\w\-.]+) ADAuditPlus""",
    """CALLER_USER_NAME\s{0,100}=\s{0,100}({user}[^\s\]]+)""",
    """CALLER_USER_DOMAIN\s{0,100}=\s{0,100}({domain}[^\s\]]+)""",
    """SOURCE\s{0,100}=\s{0,100}({src_host}[\w\-.]+)""",
    """EVENT_NUMBER\s{0,100}=\s{0,100}({event_code}\d{1,100})""",
    """CALLER_LOGON_ID\s{0,100}=\s{0,100}({logon_id}[^\s]+)""",
    """ACCOUNT_SID\s{0,100}=\s{0,100}\%\{({account_id}[^\s\}]+)""",
    """GROUP_TYPE\s{0,100}=\s{0,100}({group_type}[^\]]+?)\s{0,100}\]""",
    """was added to .+? Group '({group_name}[^']+)""",
    """MEMBER_NAME\s{0,100}=\s{0,100}(?:-|({account_dn}CN=.+?,({account_ou}OU.+?DC=[\w-]+)))""",
  ]
  DupFields=[ "host->dest_host" ]
}
```