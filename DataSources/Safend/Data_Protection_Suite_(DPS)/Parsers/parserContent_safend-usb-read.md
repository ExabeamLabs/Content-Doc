#### Parser Content
```Java
{
Name = safend-usb-read
  Vendor = Safend
  Product = Data Protection Suite (DPS)
  Lms = Direct
  DataType = "usb-activity"
  TimeFormat = "MM dd yyyy HH:mm:ss"
  Conditions = [ """[Safend Data Protection]""", """Action: Read""" ]
  Fields = [
    """exabeam_raw=({time}\d\d \d\d \d\d\d\d \d\d:\d\d:\d\d) ({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """Client GMT:\s{1,100}({time}\d{1,100}/\d{1,100}/\d\d\d\d \d\d:\d\d:\d\d (AM|PM|am|pm))""",
    """Action:\s{0,100}({activity}[^,]{1,2000}?)\s{0,100}$""",
    """User:\s{0,100}({user}[^@,\s]{1,2000})(@({domain}[^@,.\s]{1,2000}))?""",
    """User:\s{0,100}({user_email}[^,\s]{1,2000})""",
    """Computer:\s{0,100}({host}[^,]{1,2000})""",
    """Operating System:\s{0,100}({os}[^,]{1,2000})""",
    """Device Type:\s{0,100}({device_type}[^,]{1,2000})""",
    """Device Info:\s{0,100}({device_type}[^,]{1,2000}),""",
    """Distinct ID:\s{0,100}(|({device_id}[^,]{1,2000})),""",
    """({activity_details}Policy:\s{0,100}[^,]{1,2000})""",
    """File Name:\s{0,100}({file_path}[^,]{1,2000})""",
    """File Name:\s{0,100}.+?\\({file_name}[^\\,]{1,2000}),""",
    """File Name:[^,]{1,2000}\.({file_ext}\w+),""",
    """File Type:\s{0,100}({file_ext}\w+)""",
    """File Size:\s{0,100}({bytes}[^,]{1,2000})"""
  ]
}
```