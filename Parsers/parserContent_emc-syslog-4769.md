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
    """Account Name:\s+({user}[^@]+)@({domain}[\w._\-]+)""",
    """Service Name:\s+(?: |({dest_host}\S+\$))\s+Service ID""",
    """Service Name:\s+(?: |({service_name}\S+))\s+Service ID""",
    """Client Address:\s+(::[\w]+:)?({src_ip}[a-fA-F:\d.]+)""",
    """Failure Code:\s+({result_code}[\w]+)""",
    """Ticket Encryption Type:\s+({ticket_encryption_type}[^\s]+)""",
    """Ticket Options:\s+({ticket_options}[^\s]+)""" ]
}
```