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
    """exabeam_host=([^=]+@\s*)?({host}[\w\-.]+)""",
    """TIME_GENERATED\s*=\s*({time}\d+)""",
    """({host}[\w\-.]+) ADAuditPlus""",
    """USERNAME\s*=\s*({user}[^\s\]]+)""",
    """CLIENT_IP_ADDRESS\s*=\s*({dest_ip}[A-Fa-f:\d.]+)""",
    """CLIENT_HOST_NAME\s*=\s*({dest_host}[^\]]+?)\s*\]""",
    """DOMAIN\s*=\s*([^\/]+\/)?({domain}[^\\\/]+?)\s*\]""",
    """SOURCE\s*=\s*({src_host}[\w\-.]+)""",
    """RECORD_NUMBER\s*=\s*({record_id}\d+)""",
    """EVENT_NUMBER\s*=\s*({event_code}\d+)""",
    """USER_SID\s*=\s*\%\{({user_sid}[^\}]+)""",
    """ERROR_CODE\s*=\s*({result_code}[^\s]+)""",
    """EVENT_TYPE_TEXT\s*=\s*({outcome}.+?)\s*\]""",
  ]
}
```