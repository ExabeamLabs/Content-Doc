#### Parser Content
```Java
{
Name = ad-audit-4771
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-4771"
  TimeFormat = "epoch_sec"
  Conditions = [ """ADAuditPlus""", """EVENT_NUMBER = 4771""", """Kerberos pre-authentication failed""" ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}[\w\-.]+)""",
    """TIME_GENERATED\s{0,100}=\s{0,100}({time}\d{1,100})""",
    """({host}[\w\-.]+) ADAuditPlus""",
    """USERNAME\s{0,100}=\s{0,100}({user}[^\s\]]+)""",
    """CLIENT_IP_ADDRESS\s{0,100}=\s{0,100}({dest_ip}[A-Fa-f:\d.]+)""",
    """CLIENT_HOST_NAME\s{0,100}=\s{0,100}({dest_host}[^\]]+?)\s{0,100}\]""",
    """DOMAIN\s{0,100}=\s{0,100}([^\/]+\/)?({domain}[^\\\/]+?)\s{0,100}\]""",
    """SOURCE\s{0,100}=\s{0,100}({src_host}[\w\-.]+)""",
    """RECORD_NUMBER\s{0,100}=\s{0,100}({record_id}\d{1,100})""",
    """EVENT_NUMBER\s{0,100}=\s{0,100}({event_code}\d{1,100})""",
    """USER_SID\s{0,100}=\s{0,100}\%\{({user_sid}[^\}]+)""",
    """ERROR_CODE\s{0,100}=\s{0,100}({result_code}[^\s]+)""",
    """EVENT_TYPE_TEXT\s{0,100}=\s{0,100}({outcome}.+?)\s{0,100}\]""",
  ]
}
```