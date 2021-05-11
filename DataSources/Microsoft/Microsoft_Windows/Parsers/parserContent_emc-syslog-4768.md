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
    """Account Name:\s{1,100}({user}[^@]+?)(?:@([^\s]+))?\s{1,100}Supplied Realm Name""",
    """Client Address:\s{1,100}(::[\w]+:)?({dest_ip}[a-fA-F:\d.]+)""",
    """Result Code:\s{1,100}({result_code}[\w]+)""",
    """Supplied Realm Name:\s{1,100}({domain}[^\s]+)""",
    """User ID:\s{1,100}(?:NULL SID|({user_sid}.+?))\s{1,100}Service Information""",
    """Service Name:\s{0,100}({service_name}[^\s]+)""", 
    """Ticket Options:\s{0,100}({ticket_options}[^\s]+)""",
    """Ticket Encryption Type:\s{0,100}({ticket_encryption_type}[^\s]+)""",
  ]
 DupFields = ["host->dest_host"]
}
```