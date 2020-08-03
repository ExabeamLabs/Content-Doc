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
    """Action:\s*({activity}[^,]+)""",
    """User:\s*({user_email}[^,]+)""",
    """Computer:\s*({host}[^,]+)""",
    """Operating System:\s*({os}[^,]+)""",
    """Device Type:\s*({device_type}[^,]+)""",
    """Distinct ID:\s*(|({device_id}[^,]+)),""",
    """Policy:\s*({activity_details}[^,]+)""",
  ]
}
```