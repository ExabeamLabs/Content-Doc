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
    """(Information|Audit Success|Success Audit)\s+({host}[\w.\-]+)\s+""",
    """Microsoft-Windows-Security-Auditing\s+(({domain}[^\\]+)\\+)?({user}[^@\s]+)""",
    """Account Name:\s+(?=\w)({user}.+?)(@({domain}.+?))?\s+Account Domain:""",
    """Account Domain:\s+(?=\w)({domain}.+?)\s+Service Information:""",
    """Client Address:\s+(::[\w]+:)?({src_ip}.+?)\s+Client Port""",
    """Service Name:\s+(?=\w)({service_name}.+?)\s+Service ID:""",
    """Service Name:\s+(?=\w)({dest_host}.+?\$)\s+Service ID:""",
    """Ticket Options:\s+({ticket_options}.+?)\s+Ticket Encryption Type:""",
    """Ticket Encryption Type:\s+({ticket_encryption_type}[^\s]+)"""
  ]
}
```