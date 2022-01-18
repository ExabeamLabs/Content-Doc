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
  Fields = [ """exabeam_host=({host}[\w.\-]{1,2000})""",
             """EvntSLog:\s{1,100}\[.+\]\s{1,100}({time}\w+ \w+ \d{1,100} \d{1,100}:\d{1,100}:\d{1,100} \d{1,100}):\s{1,100}({host}[\w. /\\]{1,2000})\/.*\s{1,100}\(({event_code}\w+)\)""",
             """User Name:\s{1,100}({user}[^@]{1,2000})@({domain}[^\s]{1,2000})""",
             """Service Name:\s{1,100}({dest_host}\S+\$)\s""",
             """Service Name:\s{1,100}({service_name}\S+)""",
             """Client Address:\s{1,100}({src_ip}[a-fA-F:\d.]{1,2000})""",
             """Failure Code:\s{1,100}({result_code}[\w\-]{1,2000})""",
  	     """Ticket Options:\s{1,100}({ticket_options}[^\s]{1,2000})""",
  	     """Ticket Encryption Type:\s{1,100}({ticket_encryption_type}[^\s]{1,2000})""" ]


}
```