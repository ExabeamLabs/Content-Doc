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
    """exabeam_host=({host}[^\s]{1,2000})""",
    """({event_name}A Kerberos service ticket was renewed)""",
    """Account Name:\s{0,100}(Administrator|({user}[^@;\s]{1,2000}))[^=]{1,2000}?[\s;]{0,2000}Account Domain""",
    """Account Domain:\s{0,100}({domain}[^=]{1,2000}?)[\s;]{0,2000}Service Information""",
    """Service Name:\s{0,100}({service_name}[^=]{1,2000}?)[\s;]{0,2000}Service ID:""",
    """Ticket Options:\s{0,100}({ticket_options}[^=]{1,2000}?)[\s;]{0,2000}Ticket Encryption Type:""",
    """Ticket Encryption Type:\s{0,100}({ticket_encryption_type}[^\s;]{1,2000})""",
    """Client Address:\s{0,100}(::[\w]{1,2000}:)?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """Client Port:\s{0,100}({src_port}\d{1,100})""",
    """Service Name:\s{0,100}({dest_host}[^=]{1,2000}?\$)[\s;]{0,2000}Service ID:"""
  ]
}
```