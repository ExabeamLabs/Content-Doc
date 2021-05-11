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
  Fields = [ """exabeam_raw=({time}\d{1,100}/\d{1,100}/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM))""",
    """({event_name}Account Logon)""",
             """ComputerName=({host}[\w.\-]+)""",
             """EventCode=({event_code}\w+)""",
             """User Name:\s{1,100}(?:-|({user}.+?))(@({domain}[\w._\-]+))?\s{1,100}Supplied Realm""",
             """Service Name:\s{1,100}({dest_host}\S+\$)\s""",
             """Service Name:\s{1,100}({service_name}\S+)""",
             """Client Address:\s{1,100}(::[\w]+:)?({src_ip}[a-fA-F:\d.]+)""",
             """Failure Code:\s{1,100}({result_code}[\w\-]+)""",
             """Sid=({user_sid}[^\s]+)\s{1,100}SidType""",
	     """Ticket Options:\s{1,100}({ticket_options}[^\s]+)""",
	     """Ticket Encryption Type:\s{1,100}({ticket_encryption_type}[^\s]+)"""
  ]
}
```