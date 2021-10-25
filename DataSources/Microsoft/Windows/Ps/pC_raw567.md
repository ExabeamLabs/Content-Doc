#### Parser Content
```Java
{
Name = raw-567
    Vendor = Microsoft
    Product = Windows
    Lms = Direct
    DataType = "windows-567"
    IsHVF = true
    TimeFormat = "MM/dd/yyyy hh:mm:ss a"
    Conditions = ["Object Access Attempt", "Image File Name:" ]
    Fields = [
      """({event_name}Object Access Attempt)""",
	"""({time}\d\d/\d\d/\d\d\d\d \d\d:\d\d:\d\d (am|AM|pm|PM))""",
        """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
	"""(?i)(((audit|success)( |_)(success|audit))|information)\s{0,100},\s{0,100}({host}[^,]{1,2000})""",
        """Computer(\w+)?["\s]{0,2000}(:|=)\s{0,100}"?({host}.+?)("|\s)""",
        """Audit\s{0,100}({host}[^\s]{1,2000}?)\s+Object Access""",       
        """User=(?:SYSTEM|NOT_TRANSLATED|({user}.+?))\s{1,100}Sid=""",
        """567\s{0,100}Security\s{0,100}({user}[^\s]{1,1000})""",
        """({event_code}567)""",
        """Object Type:\s{1,100}({file_type}.+?)\s{1,100}Process ID:""",
        """Image File Name:\s{1,100}({file_path}.+?)\s{1,100}Accesses:""",
        """Accesses:\s{1,100}({accesses}.+?)\s{1,100}Access Mask:""",
        """Image File Name:\s{0,100}.*?\\?({file_name}([^\\]{0,2000}?)({file_ext}\.[^\\]{0,2000}?)?|[^\\]{1,2000})\s{1,100}Accesses:""",
        """Image File Name:\s{0,100}({file_parent}.+?)\\(?:[^\\]{1,2000}?)\s{1,100}Accesses:""",
        """\s{1,100}Client Address:\s{1,100}(::[\w]{1,2000}:)?({dest_ip}[a-fA-F:\d.]{1,2000})"""
     ]
  DupFields = [ "host->dest_host" ]
 }
```