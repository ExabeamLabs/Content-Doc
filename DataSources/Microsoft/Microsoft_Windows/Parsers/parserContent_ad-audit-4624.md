#### Parser Content
```Java
{
Name = ad-audit-4624
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-4624"
  TimeFormat = "epoch_sec"
  Conditions = [ """ADAuditPlus""", """EVENT_NUMBER = 4624""", """An account was successfully logged on""" ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}[\w\-.]+)""",
    """TIME_GENERATED\s{0,100}=\s{0,100}({time}\d{1,100})""",
    """({host}[\w\-.]+) ADAuditPlus""",
    """CALLER_USER_NAME\s{0,100}=\s{0,100}(-|({user}[^\s\]]+))""",
    """CLIENT_IP_ADDRESS\s{0,100}=\s{0,100}({dest_ip}[A-Fa-f:\d.]+)""",
    """CLIENT_HOST_NAME\s{0,100}=\s{0,100}({dest_host}[\w\-.]+)""",
    """CALLER_USER_DOMAIN\s{0,100}=\s{0,100}(null|-|({domain}[^\\\/\s]+))""",
    """SOURCE\s{0,100}=\s{0,100}(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|({src_host_windows}[\w\-.]+))""",
    """RECORD_NUMBER\s{0,100}=\s{0,100}({record_id}\d{1,100})""",
    """EVENT_NUMBER\s{0,100}=\s{0,100}({event_code}\d{1,100})""",
    """USER_SID\s{0,100}=\s{0,100}\%\{({user_sid}[^\}]+)""",
    """LOGON_ID\s{0,100}=\s{0,100}(null|-|({logon_id}[^\s]+))""",
    """LOGON_TYPE\s{0,100}=\s{0,100}({logon_type}\d{1,100})""",
    """LOGON_PROCESS\s{0,100}=\s{0,100}(null|-|({auth_process}[^\s]+))""",
    """AUTHENTICATION_PACKAGE\s{0,100}=\s{0,100}(null|-|({auth_package}[^\s]+))""",
    """CALLER_PROCESS_NAME\s{0,100}=\s{0,100}(?:-|null|({process}[\w:\\.\-]+))""",
    """USER_SAM_ACCOUNT_NAME\s{0,100}=\s{0,100}(-|null|({account}[^\s\]]+))""",
  ]
}
```