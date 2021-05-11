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
             """EvntSLog:\s{1,100}\[.+\]\s{1,100}({time}\w+ \w+ \d{1,100} \d{1,100}:\d{1,100}:\d{1,100} \d{1,100}):\s{1,100}({host}[\w. /\\]+)\/.*\s{1,100}\(({event_code}\w+)\)""",
             """User Name:\s{1,100}({user}[^@]+)@({domain}[^\s]+)""",
             """Service Name:\s{1,100}({dest_host}\S+\$)\s""",
             """Service Name:\s{1,100}({service_name}\S+)""",
             """Client Address:\s{1,100}({src_ip}[a-fA-F:\d.]+)""",
             """Failure Code:\s{1,100}({result_code}[\w\-]+)""",
  	     """Ticket Options:\s{1,100}({ticket_options}[^\s]+)""",
  	     """Ticket Encryption Type:\s{1,100}({ticket_encryption_type}[^\s]+)""" ]
}
```