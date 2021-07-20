#### Parser Content
```Java
{
Name = q-673
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = QRadar
  DataType = "windows-673"
  TimeFormat = "epoch_sec"
  Conditions = [ "EventIDCode=673" ]
  Fields = [
             """EventID=({event_code}\d{1,100}).+?User Domain:\s{1,100}({domain}[^\s]{1,2000})""",
             """TimeGenerated=({time}\d{1,100})""",
             """Computer=({host}[^\s]{1,2000})""",
             """User Name:\s{1,100}({user}[^@\s]{1,2000}).+?Service Name:\s{1,100}({service_name}\S+).+?Client Address:\s{1,100}({src_ip}[a-fA-F:\d.]{1,2000}).+?Failure Code:\s{1,100}({result_code}[^\s]{1,2000})""",
             """Service Name:\s{1,100}({dest_host}\S+\$)\s""",
	     """Ticket Options:\s{1,100}({ticket_options}[^\s]{1,2000})""",
	     """Ticket Encryption Type:\s{1,100}({ticket_encryption_type}[^\s]{1,2000})"""
           ]
}
```