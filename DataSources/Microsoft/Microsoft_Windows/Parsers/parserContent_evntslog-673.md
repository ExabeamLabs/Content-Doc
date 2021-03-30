#### Parser Content
```Java
{
Name = evntslog-673
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-673"
  TimeFormat = "E MMM dd HH:mm:ss yyyy"
  Conditions = [ "User Name:", "(673)" ]
  Fields = [ """exabeam_host=({host}[\w.\-]+)""",
             """EvntSLog:\s+\[.+\]\s+({time}\w+ \w+ \d+ \d+:\d+:\d+ \d+):\s+({host}[\w. /\\]+)\/.*\s+\(({event_code}\w+)\)""",
             """User Name:\s+({user}[^@]+)@({domain}[^\s]+)""",
             """Service Name:\s+({dest_host}\S+\$)\s""",
             """Service Name:\s+({service_name}\S+)""",
             """Client Address:\s+({src_ip}[a-fA-F:\d.]+)""",
             """Failure Code:\s+({result_code}[\w\-]+)""",
  	     """Ticket Options:\s+({ticket_options}[^\s]+)""",
  	     """Ticket Encryption Type:\s+({ticket_encryption_type}[^\s]+)""" ]
}
```