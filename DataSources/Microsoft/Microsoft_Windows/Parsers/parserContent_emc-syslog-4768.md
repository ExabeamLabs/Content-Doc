#### Parser Content
```Java
{
Name = emc-syslog-4768
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-4768"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "__li_source_path=", "A Kerberos authentication ticket (TGT) was requested","""eventid="4768"""" ]
  Fields = [
    """({event_name}A Kerberos authentication ticket \(TGT\) was requested)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """__li_source_path="({host}[^"]+)"""",
    """({event_code}4768)""",
    """Account Name:\s+({user}[^@]+?)(?:@([^\s]+))?\s+Supplied Realm Name""",
    """Client Address:\s+(::[\w]+:)?({dest_ip}[a-fA-F:\d.]+)""",
    """Result Code:\s+({result_code}[\w]+)""",
    """Supplied Realm Name:\s+({domain}[^\s]+)""",
    """User ID:\s+(?:NULL SID|({user_sid}.+?))\s+Service Information""",
    """Service Name:\s*({service_name}[^\s]+)""", 
    """Ticket Options:\s*({ticket_options}[^\s]+)""",
    """Ticket Encryption Type:\s*({ticket_encryption_type}[^\s]+)""",
  ]
 DupFields = ["host->dest_host"]
}
```