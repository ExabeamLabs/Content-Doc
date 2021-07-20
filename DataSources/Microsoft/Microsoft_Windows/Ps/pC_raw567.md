#### Parser Content
```Java
{
Name = raw-567
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-567"
    IsHVF = true
    TimeFormat = "MM/dd/yyyy hh:mm:ss a"
    Conditions = ["Object Access Attempt", "Image File Name:" ]
    Fields = [
      """({event_name}Object Access Attempt)""",
	"""({time}\d\d/\d\d/\d\d\d\d \d\d:\d\d:\d\d (am|AM|pm|PM))""",
	"""(?i)(((audit|success)( |_)(success|audit))|information)\s{0,100}
```