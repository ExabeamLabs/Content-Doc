#### Parser Content
```Java
{
Name = ad-audit-4723
  Vendor = Microsoft
  Product = Windows
  Lms = Direct
  DataType = "windows-password-change"
  TimeFormat = "epoch_sec"
  Conditions = [ """ADAuditPlus""", """EVENT_NUMBER = 4723""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
    """TIME_GENERATED\s{0,100}=\s{0,100}({time}\d{1,100})""",
    """({host}[\w\-.]{1,2000}) ADAuditPlus""",
    """CALLER_USER_NAME\s{0,100}=\s{0,100}({user}[^\s\]]{1,2000})""",
    """CALLER_USER_DOMAIN\s{0,100}=\s{0,100}({domain}[^\s\]]{1,2000})""",
    """SOURCE\s{0,100}=\s{0,100}({src_host}[\w\-.]{1,2000})""",
    """RECORD_NUMBER\s{0,100}=\s{0,100}({record_id}\d{1,100})""",
    """EVENT_NUMBER\s{0,100}=\s{0,100}({event_code}\d{1,100})""",
    """CALLER_USER_SID\s{0,100}=\s{0,100}({user_sid}[^\s]{1,2000})""",
    """CALLER_LOGON_ID\s{0,100}=\s{0,100}({logon_id}[^\s]{1,2000})""",
    """ACCOUNT_NAME\s{0,100}=\s{0,100}({target_user}[^\s]{1,2000})""",
    """ACCOUNT_DOMAIN\s{0,100}=\s{0,100}({target_domain}[^\s]{1,2000})""",
    """ACCOUNT_SID\s{0,100}=\s{0,100}\%\{({target_user_sid}[^\s\}]{1,2000})""",
    """EVENT_TYPE_TEXT\s{0,100}=\s{0,100}({outcome}[^\s]{1,2000})""",
    ]
  DupFields = [ "host->dest_host" ]
}
}
```