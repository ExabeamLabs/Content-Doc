#### Parser Content
```Java
{
Name = ad-audit-4768
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-4768"
  TimeFormat = "epoch_sec"
  Conditions = [ """ADAuditPlus""", """EVENT_NUMBER = 4768""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
    """TIME_GENERATED\s{0,100}=\s{0,100}({time}\d{1,100})""",
    """({host}[\w\-.]{1,2000}) ADAuditPlus""",
    """USERNAME\s{0,100}=\s{0,100}({user}[^\s\]@]{1,2000})\s{0,100}\]""",
    """USERNAME\s{0,100}=\s{0,100}({user_email}[^\s\]@]{1,2000}@[^\s\]@]{1,2000})\s{0,100}\]""",
    """CLIENT_IP_ADDRESS\s{0,100}=\s{0,100}({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """DOMAIN\s{0,100}=\s{0,100}({domain}[^\\\/\]]{1,2000}?)\s{0,100}\]""",
    """RECORD_NUMBER\s{0,100}=\s{0,100}({record_id}\d{1,100})""",
    """EVENT_NUMBER\s{0,100}=\s{0,100}({event_code}\d{1,100})""",
    """USER_SID\s{0,100}=\s{0,100}\%?\{?({user_sid}[^\}\s\]]{1,2000})""",
    """ERROR_CODE\s{0,100}=\s{0,100}({result_code}[^\s]{1,2000})""",
    """EVENT_TYPE_TEXT\s{0,100}=\s{0,100}({outcome}.+?)\s{0,100}\]""",
    """LOGON_SERVICE\s{0,100}=\s{0,100}(null|-|({service_name}[^\s\]]{1,2000}))""",
    """TICKET_OPTIONS\s{0,100}=\s{0,100}(null|-|({ticket_options}[^\s\]]{1,2000}))""",
    """TICKET_ENCRYPTION_TYPE\s{0,100}=\s{0,100}(null|-|({ticket_encryption_type}[^\s\]]{1,2000}))""",
  ]
}
```