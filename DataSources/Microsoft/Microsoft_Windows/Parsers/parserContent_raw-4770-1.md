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
    """Account Name:\s{0,100}(Administrator|({user}[^@;\s]+))[^=]+?[\s;]*Account Domain""",
    """Account Domain:\s{0,100}({domain}[^=]+?)[\s;]*Service Information""",
    """Service Name:\s{0,100}({service_name}[^=]+?)[\s;]*Service ID:""",
    """Ticket Options:\s{0,100}({ticket_options}[^=]+?)[\s;]*Ticket Encryption Type:""",
    """Ticket Encryption Type:\s{0,100}({ticket_encryption_type}[^\s;]+)""",
    """Client Address:\s{0,100}(::[\w]+:)?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """Client Port:\s{0,100}({src_port}\d{1,100})""",
    """Service Name:\s{0,100}({dest_host}[^=]+?\$)[\s;]*Service ID:"""
  ]
}
```