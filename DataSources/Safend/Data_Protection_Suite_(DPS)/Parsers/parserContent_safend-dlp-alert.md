#### Parser Content
```Java
{
Name = safend-dlp-alert
  Vendor = Safend
  Product = Data Protection Suite (DPS)
  Lms = Direct
  DataType = "dlp-alert"
  TimeFormat = "M d yyyy HH:mm:ss"
  Conditions = [ """[Safend Data Protection]""", """ Client Alert details:""" ]
  Fields = [ 
    """exabeam_raw=({time}\d\d \d\d \d\d\d\d \d\d:\d\d:\d\d) ({dest_ip}[A-Fa-f:\d.]+)""",
    """Client GMT:\s+({time}\d+/\d+/\d\d\d\d \d\d:\d\d:\d\d (AM|PM|am|pm))""",
    """Action:\s*({outcome}[^,]+)""",
    """User:\s+({user}[^@,\s]+)(@({domain}[^@,.\s]+))?""",
    """User:\s*({user_email}[^\s,]+)""",
    """Computer:\s*({host}[^,]+)""",
    """Operating System:\s*({os}[^,]+)""",
    """Policy:\s*({alert_name}[^,]+)""",
    """Policy:\s*.+?\-\s*({alert_type}[^,\-]+?)\s*\-""",
    """Scope:\s*({alert_type}[^,]+),""",
    """({additional_info}Device Info:\s*\S[^:]+?),\s+[^,:]+?:""",
    """Device Type:\s*(?:N/A|({protocol}[^,]+))""",
    """Distinct ID:\s*(|({device_id}[^,]+)),""",
    """Details:\s*Disk size = (?i)({bytes}\d+\s+\w+)""",
    """Details:\s*({process_name}[^=:,]+?)(,|\s*$)"""
  ]
}
```