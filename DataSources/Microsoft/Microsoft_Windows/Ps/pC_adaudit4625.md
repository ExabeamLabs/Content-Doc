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
    """TIME_GENERATED\s{0,100}=\s{0,100}({time}\d{1,100})""",
    """({host}[\w\-.]{1,2000}) ADAuditPlus""",
    """USERNAME\s{0,100}=\s{0,100}({user}[^\s\]]{1,2000})""",
    """CLIENT_IP_ADDRESS\s{0,100}=\s{0,100}({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """CLIENT_HOST_NAME\s{0,100}=\s{0,100}({dest_host}[\w\-.]{1,2000})""",
    """DOMAIN\s{0,100}=\s{0,100}({domain}[^\\\/\s]{1,2000})""",
    """SOURCE\s{0,100}=\s{0,100}({src_host}[\w\-.]{1,2000})""",
    """RECORD_NUMBER\s{0,100}=\s{0,100}({record_id}\d{1,100})""",
    """EVENT_NUMBER\s{0,100}=\s{0,100}({event_code}\d{1,100})""",
    """USER_SID\s{0,100}=\s{0,100}({user_sid}[^\s]{1,2000})""",
    """LOGON_ID\s{0,100}=\s{0,100}(null|({logon_id}[^\s]{1,2000}))""",
    """LOGON_TYPE\s{0,100}=\s{0,100}({logon_type}\d{1,100})""",
    """LOGON_PROCESS\s{0,100}=\s{0,100}(null|({auth_process}[^\s]{1,2000}))""",
    """AUTHENTICATION_PACKAGE\s{0,100}=\s{0,100}({auth_package}[^\s]{1,2000})""",
    """CALLER_PROCESS_NAME\s{0,100}=\s{0,100}(|null|-|({process}({directory}(\w:)?(?:[^:\]]{1,2000})?[\\\/])?({process_name}[^\\\/"\]]{1,2000}?)))\s{0,100}\]""",
    """CALLER_USER_NAME\s{0,100}=\s{0,100}(-|({caller_user}[^\s]{1,2000}))""",
    """CALLER_USER_DOMAIN\s{0,100}=\s{0,100}(-|({caller_domain}[^\s]{1,2000}))""",
    """FAILURE_STATUS\s{0,100}=\s{0,100}({result_code}[^\s]{1,2000})"""
    """FAILURE_SUB_STATUS\s{0,100}=\s{0,100}({result_code}[^\s]{1,2000})"""
  ]
  DupFields = [ "directory->process_directory" ]


}
```