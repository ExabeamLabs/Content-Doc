#### Parser Content
```Java
{
Name = nic-4770
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = RsaSa
  DataType = "windows-4770"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ "MSWinEventLog", "4770 Microsoft-Windows-Security-Auditing", "A Kerberos service ticket was renewed" ]
  Fields = [
    """({event_name}A Kerberos service ticket was renewed)""",
    """({time}\w{3}\s\d{2}\s\d{2}:\d{2}:\d{2}\s\d{4})""",
    """({event_code}4770)""",
    """(Information|Audit Success|Success Audit)\s{1,100}({host}[\w.\-]{1,2000})\s{1,100}""",
    """Microsoft-Windows-Security-Auditing\s{1,100}(({domain}[^\\]{1,2000})\\+)?({user}[^@\s]{1,2000})""",
    """Account Name:\s{1,100}(?=\w)({user}.+?)(@({domain}.+?))?\s{1,100}Account Domain:""",
    """Account Domain:\s{1,100}(?=\w)({domain}.+?)\s{1,100}Service Information:""",
    """Client Address:\s{1,100}(::[\w]{1,2000}:)?({src_ip}.+?)\s{1,100}Client Port""",
    """Service Name:\s{1,100}(?=\w)({service_name}.+?)\s{1,100}Service ID:""",
    """Service Name:\s{1,100}(?=\w)({dest_host}.+?\$)\s{1,100}Service ID:""",
    """Ticket Options:\s{1,100}({ticket_options}.+?)\s{1,100}Ticket Encryption Type:""",
    """Ticket Encryption Type:\s{1,100}({ticket_encryption_type}[^\s]{1,2000})"""
  ]
}
```