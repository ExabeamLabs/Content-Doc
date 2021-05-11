#### Parser Content
```Java
{
Name = emc-syslog-4769
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-4769"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "__li_source_path=", "A Kerberos service ticket was requested","""eventid="4769"""" ]
  Fields = [
    """({event_name}A Kerberos service ticket was requested)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """__li_source_path="({host}[^"]+)"""",
    """({event_code}4769)""",
    """Account Name:\s{1,100}({user}[^@]+)@({domain}[\w._\-]+)""",
    """Service Name:\s{1,100}(?: |({dest_host}\S+\$))\s{1,100}Service ID""",
    """Service Name:\s{1,100}(?: |({service_name}\S+))\s{1,100}Service ID""",
    """Client Address:\s{1,100}(::[\w]+:)?({src_ip}[a-fA-F:\d.]+)""",
    """Failure Code:\s{1,100}({result_code}[\w]+)""",
    """Ticket Encryption Type:\s{1,100}({ticket_encryption_type}[^\s]+)""",
    """Ticket Options:\s{1,100}({ticket_options}[^\s]+)""" ]
}
```