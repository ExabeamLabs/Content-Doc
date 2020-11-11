#### Parser Content
```Java
{
Name = ad-audit-4624
  Vendor = AD Audit
  Product = AD Audit
  Lms = Direct
  DataType = "windows-4624"
  TimeFormat = "epoch_sec"
  Conditions = [ """ADAuditPlus""", """EVENT_NUMBER = 4624""", """An account was successfully logged on""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}[\w\-.]+)""",
    """TIME_GENERATED\s*=\s*({time}\d+)""",
    """({host}[\w\-.]+) ADAuditPlus""",
    """CALLER_USER_NAME\s*=\s*(-|({user}[^\s\]]+))""",
    """CLIENT_IP_ADDRESS\s*=\s*({dest_ip}[A-Fa-f:\d.]+)""",
    """CLIENT_HOST_NAME\s*=\s*({dest_host}[\w\-.]+)""",
    """CALLER_USER_DOMAIN\s*=\s*(null|-|({domain}[^\\\/\s]+))""",
    """SOURCE\s*=\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|({src_host_windows}[\w\-.]+))""",
    """RECORD_NUMBER\s*=\s*({record_id}\d+)""",
    """EVENT_NUMBER\s*=\s*({event_code}\d+)""",
    """USER_SID\s*=\s*\%\{({user_sid}[^\}]+)""",
    """LOGON_ID\s*=\s*(null|-|({logon_id}[^\s]+))""",
    """LOGON_TYPE\s*=\s*({logon_type}\d+)""",
    """LOGON_PROCESS\s*=\s*(null|-|({auth_process}[^\s]+))""",
    """AUTHENTICATION_PACKAGE\s*=\s*(null|-|({auth_package}[^\s]+))""",
    """CALLER_PROCESS_NAME\s*=\s*(?:-|null|({process}[\w:\\.\-]+))""",
  ]
}
```