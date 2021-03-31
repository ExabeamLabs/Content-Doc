#### Parser Content
```Java
{
Name = raw-4770-1
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-4770"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """A Kerberos service ticket was renewed""", """Account Domain:""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)"""
    """exabeam_host=({host}[^\s]+)""",
    """({event_name}A Kerberos service ticket was renewed)""",
    """Account Name:\s*(Administrator|({user}[^@;\s]+))[^=]+?[\s;]*Account Domain""",
    """Account Domain:\s*({domain}[^=]+?)[\s;]*Service Information""",
    """Service Name:\s*({service_name}[^=]+?)[\s;]*Service ID:""",
    """Ticket Options:\s*({ticket_options}[^=]+?)[\s;]*Ticket Encryption Type:""",
    """Ticket Encryption Type:\s*({ticket_encryption_type}[^\s;]+)""",
    """Client Address:\s*(::[\w]+:)?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """Client Port:\s*({src_port}\d+)""",
    """Service Name:\s*({dest_host}[^=]+?\$)[\s;]*Service ID:"""
  ]
}
```