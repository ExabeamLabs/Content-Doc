#### Parser Content
```Java
{
Name = ad-audit-4724
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-password-reset"
  TimeFormat = "epoch_sec"
  Conditions = [ """ADAuditPlus""", """EVENT_NUMBER = 4724""", """User Account password set""" ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}[\w\-.]+)""",
    """TIME_GENERATED\s{0,100}=\s{0,100}({time}\d{1,100})""",
    """({host}[\w\-.]+) ADAuditPlus""",
    """CALLER_USER_NAME\s{0,100}=\s{0,100}({user}[^\s\]]+)""",
    """CALLER_USER_DOMAIN\s{0,100}=\s{0,100}({domain}[^\s\]]+)""",
    """SOURCE\s{0,100}=\s{0,100}({src_host}[\w\-.]+)""",
    """RECORD_NUMBER\s{0,100}=\s{0,100}({record_id}\d{1,100})""",
    """EVENT_NUMBER\s{0,100}=\s{0,100}({event_code}\d{1,100})""",
    """CALLER_USER_SID\s{0,100}=\s{0,100}({user_sid}[^\s]+)""",
    """CALLER_LOGON_ID\s{0,100}=\s{0,100}({logon_id}[^\s]+)""",
    """ACCOUNT_NAME\s{0,100}=\s{0,100}({target_user}[^\s]+)""",
    """ACCOUNT_DOMAIN\s{0,100}=\s{0,100}({target_domain}[^\s]+)""",
    """ACCOUNT_SID\s{0,100}=\s{0,100}\%?\{?({target_user_sid}[^\s\}]+)""",
    """EVENT_TYPE_TEXT\s{0,100}=\s{0,100}({outcome}[^\s]+)""",
  ]
  DupFields=[ "host->dest_host" ]
}
```