#### Parser Content
```Java
{
Name = s-673
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-673"
  TimeFormat = "MM/dd/yyyy hh:mm:ss a"
  Conditions = [ "EventCode=673", "User Name:" ]
  Fields = [ """exabeam_raw=({time}\d+/\d+/\d+ \d+:\d+:\d+ (am|AM|pm|PM))""",
    """({event_name}Account Logon)""",
             """ComputerName=({host}[\w.\-]+)""",
             """EventCode=({event_code}\w+)""",
             """User Name:\s+(?:-|({user}.+?))(@({domain}[\w._\-]+))?\s+Supplied Realm""",
             """Service Name:\s+({dest_host}\S+\$)\s""",
             """Service Name:\s+({service_name}\S+)""",
             """Client Address:\s+(::[\w]+:)?({src_ip}[a-fA-F:\d.]+)""",
             """Failure Code:\s+({result_code}[\w\-]+)""",
             """Sid=({user_sid}[^\s]+)\s+SidType""",
	     """Ticket Options:\s+({ticket_options}[^\s]+)""",
	     """Ticket Encryption Type:\s+({ticket_encryption_type}[^\s]+)"""
  ]
}
```