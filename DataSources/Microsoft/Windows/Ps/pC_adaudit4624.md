#### Parser Content
```Java
{
Name = ad-audit-4624
  Vendor = Microsoft
  Product = Windows
  Lms = Direct
  DataType = "windows-4624"
  TimeFormat = "epoch_sec"
  Conditions = [ """ADAuditPlus""", """EVENT_NUMBER = 4624""", """An account was successfully logged on""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
    """TIME_GENERATED\s{0,100}=\s{0,100}({time}\d{1,100})""",
    """({host}[\w\-.]{1,2000}) ADAuditPlus""",
    """CALLER_USER_NAME\s{0,100}=\s{0,100}(-|({user}[^\s\]]{1,2000}))""",
    """CLIENT_IP_ADDRESS\s{0,100}=\s{0,100}({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """CLIENT_HOST_NAME\s{0,100}=\s{0,100}({src_host}[\w\-.]{1,2000})""",
    """CALLER_USER_DOMAIN\s{0,100}=\s{0,100}(null|-|({domain}[^\\\/\s]{1,2000}))""",
    """SOURCE\s{0,100}=\s{0,100}(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|({dest_host}[\w\-.]{1,2000}))""",
    """RECORD_NUMBER\s{0,100}=\s{0,100}({record_id}\d{1,100})""",
    """EVENT_NUMBER\s{0,100}=\s{0,100}({event_code}\d{1,100})""",
    """USER_SID\s{0,100}=\s{0,100}\%\{({user_sid}[^\}]{1,2000})""",
    """LOGON_ID\s{0,100}=\s{0,100}(null|-|({logon_id}[^\s]{1,2000}))""",
    """LOGON_TYPE\s{0,100}=\s{0,100}({logon_type}\d{1,100})""",
    """LOGON_PROCESS\s{0,100}=\s{0,100}(null|-|({auth_process}[^\s]{1,2000}))""",
    """AUTHENTICATION_PACKAGE\s{0,100}=\s{0,100}(null|-|({auth_package}[^\s]{1,2000}))""",
    """CALLER_PROCESS_NAME\s{0,100}=\s{0,100}(?:-|null|({process}[\w:\\.\-]{1,2000}?\\{1,20}({process_name}[^\\\]]{1,2000})))\s{1,100}\]""",
    """USER_SAM_ACCOUNT_NAME\s{0,100}=\s{0,100}(-|null|({account}[^\s\]]{1,2000}))""",
    """REMARKS\s{0,100}=\s{0,100}({event_name}[^\]]{1,2000}?)\s{0,100}\]""",
    """KEY_LENGTH\s{0,100}=\s{0,100}({key_length}\d{1,2000})\s{1,100}\]"""
  ]


}
```