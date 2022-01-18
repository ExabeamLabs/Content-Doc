#### Parser Content
```Java
{
Name = ad-audit-5137
  Conditions = [ """ADAuditPlus""", """[ EVENT_NUMBER = 5137 ]""", """[ SOURCE =""", """[ FORMAT_MESSAGE =""" ]

ad-audit-ds-access = {
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-ds-access"
  TimeFormat = "epoch_sec"
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
    """TIME_GENERATED\s{0,100}=\s{0,100}({time}\d{1,100})""",
    """({host}[\w\-.]{1,2000}) ADAuditPlus""",
    """CLIENT_USER_NAME\s{0,100}=\s{0,100}(null|-|SYSTEM|({user}[^\s\]]{1,2000}))\s{0,100}\]""",
    """CLIENT_USER_DOMAIN\s{0,100}=\s{0,100}(null|-|NT AUTHORITY|({domain}[^\s\]]{1,2000}))\s{0,100}\]""",
    """CALLER_USER_NAME\s{0,100}=\s{0,100}(null|-|SYSTEM|({user}[^\s\]]{1,2000}))\s{0,100}\]""",
    """CALLER_USER_DOMAIN\s{0,100}=\s{0,100}(null|-|NT AUTHORITY|({domain}[^\s\]]{1,2000}))\s{0,100}\]""",
    """SOURCE\s{0,100}=\s{0,100}({src_host}[\w\-.]{1,2000})""",
    """RECORD_NUMBER\s{0,100}=\s{0,100}({record_id}\d{1,100})""",
    """EVENT_NUMBER\s{0,100}=\s{0,100}({event_code}\d{1,100})""",
    """CALLER_USER_SID\s{0,100}=\s{0,100}\%?\{?({user_sid}[^\s\}]{1,2000})""",
    """CALLER_LOGON_ID\s{0,100}=\s{0,100}(null|-|({logon_id}[^\s]{1,2000}))""",
    """ATTRIBUTES_TEXT\s{0,100}=\s{0,100}(-|null|({attribute}[^\s]{1,2000}))""",
    """ACCOUNT_NAME\s{0,100}=\s{0,100}(null|-|({object}[^\s]{1,2000}))""",
    """FORMAT_MESSAGE\s{0,100}=\s{0,100}(null|-|({object_class}[^\']{1,2000}?))\s{0,100}'""",
    """REMARKS\s{0,100}=\s{0,100}(null|-|({activity_type}[^\]]{1,2000}?))\s{0,100}\]""",
    """ATTRIBUTES_NEW_VALUE\s{0,100}=\s{0,100}(null|-|({new_attribute}[^\]]{1,2000}?))\s{0,100}\]""",
    """ATTRIBUTES_OLD_VALUE\s{0,100}=\s{0,100}(null|-|({old_attribute}[^\]]{1,2000}?))\s{0,100}\]""",
    """CLIENT_IP_ADDRESS\s{0,100}=\s{0,100}(null|-|({src_ip}[a-fA-F:\d.]{1,2000}))""" 
  ]
  DupFields =[ "host->dest_host", "activity_type->event_name", "object_class->additional_info" 
}
```