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
    """exabeam_host=([^=]+@\s{0,100})?({host}[\w\-.]+)""",
    """TIME_GENERATED\s{0,100}=\s{0,100}({time}\d{1,100})""",
    """({host}[\w\-.]+) ADAuditPlus""",
    """USERNAME\s{0,100}=\s{0,100}({user}[^\s\]@]+)\s{0,100}\]""",
    """USERNAME\s{0,100}=\s{0,100}({user_email}[^\s\]@]+@[^\s\]@]+)\s{0,100}\]""",
    """CLIENT_IP_ADDRESS\s{0,100}=\s{0,100}({dest_ip}[A-Fa-f:\d.]+)""",
    """DOMAIN\s{0,100}=\s{0,100}({domain}[^\\\/\]]+?)\s{0,100}\]""",
    """RECORD_NUMBER\s{0,100}=\s{0,100}({record_id}\d{1,100})""",
    """EVENT_NUMBER\s{0,100}=\s{0,100}({event_code}\d{1,100})""",
    """USER_SID\s{0,100}=\s{0,100}\%?\{?({user_sid}[^\}\s\]]+)""",
    """ERROR_CODE\s{0,100}=\s{0,100}({result_code}[^\s]+)""",
    """EVENT_TYPE_TEXT\s{0,100}=\s{0,100}({outcome}.+?)\s{0,100}\]""",
    """LOGON_SERVICE\s{0,100}=\s{0,100}(null|-|({service_name}[^\s\]]+))""",
    """TICKET_OPTIONS\s{0,100}=\s{0,100}(null|-|({ticket_options}[^\s\]]+))""",
    """TICKET_ENCRYPTION_TYPE\s{0,100}=\s{0,100}(null|-|({ticket_encryption_type}[^\s\]]+))""",
  ]
}
```