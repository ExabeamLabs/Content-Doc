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
    """Client GMT:\s{1,100}({time}\d{1,100}/\d{1,100}/\d\d\d\d \d\d:\d\d:\d\d (AM|PM|am|pm))""",
    """Action:\s{0,100}({activity}[^,]+?)\s{0,100}$""",
    """User:\s{0,100}({user}[^@,\s]+)(@({domain}[^@,.\s]+))?""",
    """User:\s{0,100}({user_email}[^,\s]+)""",
    """Computer:\s{0,100}({host}[^,]+)""",
    """Operating System:\s{0,100}({os}[^,]+)""",
    """Device Type:\s{0,100}({device_type}[^,]+)""",
    """Device Info:\s{0,100}({device_type}[^,]+),""",
    """Distinct ID:\s{0,100}(|({device_id}[^,]+)),""",
    """({activity_details}Policy:\s{0,100}[^,]+)""",
    """File Name:\s{0,100}({file_path}[^,]+)""",
    """File Name:\s{0,100}.+?\\({file_name}[^\\,]+),""",
    """File Name:[^,]+\.({file_ext}\w+),""",
    """File Type:\s{0,100}({file_ext}\w+)""",
    """File Size:\s{0,100}({bytes}[^,]+)"""
  ]
}
```