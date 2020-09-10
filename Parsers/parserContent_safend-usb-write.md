#### Parser Content
```Java
{
Name = safend-usb-write
  Vendor = Safend
  Product = Data Protection Suite (DPS)
  Lms = Direct
  DataType = "usb-activity"
  TimeFormat = "MM dd yyyy HH:mm:ss"
  Conditions = [ """[Safend Data Protection]""", """Action: Write""" ]
  Fields = [
    """exabeam_raw=({time}\d\d \d\d \d\d\d\d \d\d:\d\d:\d\d) ({dest_ip}[A-Fa-f:\d.]+)""",
    """Client GMT:\s+({time}\d+/\d+/\d\d\d\d \d\d:\d\d:\d\d (AM|PM|am|pm))""",
    """Action:\s*({activity}[^,]+?)\s*$""",
    """User:\s*({user}[^@,\s]+)(@({domain}[^@,.\s]+))?""",
    """User:\s*({user_email}[^,\s]+)""",
    """Computer:\s*({host}[^,]+)""",
    """Operating System:\s*({os}[^,]+)""",
    """Device Type:\s*({device_type}[^,]+)""",
    """Device Info:\s*({device_type}[^,]+),""",
    """Distinct ID:\s*(|({device_id}[^,]+)),""",
    """({activity_details}Policy:\s*[^,]+)""",
    """File Name:\s*({file_path}[^,]+)""",
    """File Name:\s*.+?\\({file_name}[^\\,]+),""",
    """File Name:[^,]+\.({file_ext}\w+),""",
    """File Type:\s*({file_ext}\w+)""",
    """File Size:\s*({bytes}[^,]+)"""
  ]
}
```