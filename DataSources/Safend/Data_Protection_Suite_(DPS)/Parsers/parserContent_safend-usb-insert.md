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
    """exabeam_raw=({time}\d\d \d\d \d\d\d\d \d\d:\d\d:\d\d) ({dest_ip}[A-Fa-f:\d.]+)""",
    """Action:\s{0,100}({activity}[^,]+)""",
    """User:\s{0,100}({user_email}[^,]+)""",
    """Computer:\s{0,100}({host}[^,]+)""",
    """Operating System:\s{0,100}({os}[^,]+)""",
    """Device Type:\s{0,100}({device_type}[^,]+)""",
    """Distinct ID:\s{0,100}(|({device_id}[^,]+)),""",
    """Policy:\s{0,100}({activity_details}[^,]+)""",
  ]
}
```