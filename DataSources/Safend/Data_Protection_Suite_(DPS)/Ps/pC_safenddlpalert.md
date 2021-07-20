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
    """exabeam_raw=({time}\d\d \d\d \d\d\d\d \d\d:\d\d:\d\d) ({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """Client GMT:\s{1,100}({time}\d{1,100}/\d{1,100}/\d\d\d\d \d\d:\d\d:\d\d (AM|PM|am|pm))""",
    """Action:\s{0,100}({outcome}[^,]{1,2000})""",
    """User:\s{1,100}({user}[^@,\s]{1,2000})(@({domain}[^@,.\s]{1,2000}))?""",
    """User:\s{0,100}({user_email}[^\s,]{1,2000})""",
    """Computer:\s{0,100}({host}[^,]{1,2000})""",
    """Operating System:\s{0,100}({os}[^,]{1,2000})""",
    """Policy:\s{0,100}({alert_name}[^,]{1,2000})""",
    """Policy:\s{0,100}.+?\-\s{0,100}({alert_type}[^,\-]{1,2000}?)\s{0,100}\-""",
    """Scope:\s{0,100}({alert_type}[^,]{1,2000}),""",
    """({additional_info}Device Info:\s{0,100}\S[^:]{1,2000}?),\s{1,100}[^,:]{1,2000}?:""",
    """Device Type:\s{0,100}(?:N/A|({protocol}[^,]{1,2000}))""",
    """Distinct ID:\s{0,100}(|({device_id}[^,]{1,2000})),""",
    """Details:\s{0,100}Disk size = (?i)({bytes}\d{1,100}\s{1,100}\w+)""",
    """Details:\s{0,100}({process_name}[^=:,]{1,2000}?)(,|\s{0,100}$)"""
  ]
}
```