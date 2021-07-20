#### Parser Content
```Java
{
Name = safend-usb-insert
  Vendor = Safend
  Product = Data Protection Suite (DPS)
  Lms = Direct
  DataType = "usb-activity"
  TimeFormat = "MM dd yyyy HH:mm:ss"
  Conditions = [ """[Safend Data Protection]""", """Action: Allowed,""" ]
  Fields = [
    """exabeam_raw=({time}\d\d \d\d \d\d\d\d \d\d:\d\d:\d\d) ({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """Action:\s{0,100}({activity}[^,]{1,2000})""",
    """User:\s{0,100}({user_email}[^,]{1,2000})""",
    """Computer:\s{0,100}({host}[^,]{1,2000})""",
    """Operating System:\s{0,100}({os}[^,]{1,2000})""",
    """Device Type:\s{0,100}({device_type}[^,]{1,2000})""",
    """Distinct ID:\s{0,100}(|({device_id}[^,]{1,2000})),""",
    """Policy:\s{0,100}({activity_details}[^,]{1,2000})""",
  ]
}
```