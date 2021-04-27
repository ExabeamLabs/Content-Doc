#### Parser Content
```Java
{
Name = ad-audit-4625
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "failed-logon"
  TimeFormat = "epoch_sec"
  Conditions = [ """ADAuditPlus""", """EVENT_NUMBER = 4625""" ]
  Fields = [
    """TIME_GENERATED\s*=\s*({time}\d+)""",
    """({host}[\w\-.]+) ADAuditPlus""",
    """USERNAME\s*=\s*({user}[^\s\]]+)""",
    """CLIENT_IP_ADDRESS\s*=\s*({dest_ip}[A-Fa-f:\d.]+)""",
    """CLIENT_HOST_NAME\s*=\s*({dest_host}[\w\-.]+)""",
    """DOMAIN\s*=\s*({domain}[^\\\/\s]+)""",
    """SOURCE\s*=\s*({src_host}[\w\-.]+)""",
    """RECORD_NUMBER\s*=\s*({record_id}\d+)""",
    """EVENT_NUMBER\s*=\s*({event_code}\d+)""",
    """USER_SID\s*=\s*({user_sid}[^\s]+)""",
    """LOGON_ID\s*=\s*(null|({logon_id}[^\s]+))""",
    """LOGON_TYPE\s*=\s*({logon_type}\d+)""",
    """LOGON_PROCESS\s*=\s*(null|({auth_process}[^\s]+))""",
    """AUTHENTICATION_PACKAGE\s*=\s*({auth_package}[^\s]+)""",
    """CALLER_PROCESS_NAME\s*=\s*(null|-||({process}({directory}(\w:)?(?:[^:\]]+)?[\\\/])?({process_name}[^\\\/"\]]+?)))\s*\]""",
    """CALLER_USER_NAME\s*=\s*(-|({caller_user}[^\s]+))""",
    """CALLER_USER_DOMAIN\s*=\s*(-|({caller_domain}[^\s]+))""",
  ]
  DupFields = [ "directory->process_directory" ]
}
```