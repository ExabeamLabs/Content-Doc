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
    """__li_source_path="({host}[^"]{1,2000})"""",
    """({event_code}4768)""",
    """Account Name:\s{1,100}({user}[^@]{1,2000}?)(?:@([^\s]{1,2000}))?\s{1,100}Supplied Realm Name""",
    """Client Address:\s{1,100}(::[\w]{1,2000}:)?({dest_ip}[a-fA-F:\d.]{1,2000})""",
    """Result Code:\s{1,100}({result_code}[\w]{1,2000})""",
    """Supplied Realm Name:\s{1,100}({domain}[^\s]{1,2000})""",
    """User ID:\s{1,100}(?:NULL SID|({user_sid}.+?))\s{1,100}Service Information""",
    """Service Name:\s{0,100}({service_name}[^\s]{1,2000})""", 
    """Ticket Options:\s{0,100}({ticket_options}[^\s]{1,2000})""",
    """Ticket Encryption Type:\s{0,100}({ticket_encryption_type}[^\s]{1,2000})""",
  ]
 DupFields = ["host->dest_host"]
}
```