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
    """Client GMT:\s{1,100}({time}\d{1,100}/\d{1,100}/\d\d\d\d \d\d:\d\d:\d\d (AM|PM|am|pm))""",
    """Action:\s{0,100}({outcome}[^,]+)""",
    """User:\s{1,100}({user}[^@,\s]+)(@({domain}[^@,.\s]+))?""",
    """User:\s{0,100}({user_email}[^\s,]+)""",
    """Computer:\s{0,100}({host}[^,]+)""",
    """Operating System:\s{0,100}({os}[^,]+)""",
    """Policy:\s{0,100}({alert_name}[^,]+)""",
    """Policy:\s{0,100}.+?\-\s{0,100}({alert_type}[^,\-]+?)\s{0,100}\-""",
    """Scope:\s{0,100}({alert_type}[^,]+),""",
    """({additional_info}Device Info:\s{0,100}\S[^:]+?),\s{1,100}[^,:]+?:""",
    """Device Type:\s{0,100}(?:N/A|({protocol}[^,]+))""",
    """Distinct ID:\s{0,100}(|({device_id}[^,]+)),""",
    """Details:\s{0,100}Disk size = (?i)({bytes}\d{1,100}\s{1,100}\w+)""",
    """Details:\s{0,100}({process_name}[^=:,]+?)(,|\s{0,100}$)"""
  ]
}
```