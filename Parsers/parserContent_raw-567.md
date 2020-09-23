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

{
  Name = r-nic-4771
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = RsaSa
  DataType = "windows-4771"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ "Kerberos pre-authentication failed", ",4771,Microsoft-Windows-Security-Auditing", "rsa_sa_log" ]
  Fields = [
    """({event_name}Kerberos pre-authentication failed)""",
    """(Mon|Tue|Wed|Thu|Fri|Sat|Sun) ({time}\w+ \d+ \d+:\d+:\d+ \d+)""",
    """Security,(rn=)?({record_id}[\d]+)""",
    """Failure Audit,({host}[^,]+)""",
    """\d{2}:\d{2}:\d{2} \d{4}
```