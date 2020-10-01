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
	"""(?i)(((audit|success)( |_)(success|audit))|information)\s*,\s*({host}[^,]+)""",
        """Computer(\w+)?["\s]*(:|=)\s*"?({host}.+?)("|\s)""",
        """User=(?:SYSTEM|NOT_TRANSLATED|({user}.+?))\s+Sid=""",
        """({event_code}567)""",
        """Object Type:\s+({file_type}.+?)\s+Process ID:""",
        """Image File Name:\s+({file_path}.+?)\s+Accesses:""",
        """Accesses:\s+({accesses}.+?)\s+Access Mask:""",
        """Image File Name:\s*.*?\\?({file_name}([^\\]*?)({file_ext}\.[^\\]*?)?|[^\\]+)\s+Accesses:""",
        """Image File Name:\s*({file_parent}.+?)\\(?:[^\\]+?)\s+Accesses:""",
        """\s+Client Address:\s+(::[\w]+:)?({dest_ip}[a-fA-F:\d.]+)"""
     ]
  DupFields = [ "host->dest_host" ]
 }
```