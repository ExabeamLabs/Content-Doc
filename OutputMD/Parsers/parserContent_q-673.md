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
             """EventID=({event_code}\d+).+?User Domain:\s+({domain}[^\s]+)""",
             """TimeGenerated=({time}\d+)""",
             """Computer=({host}[^\s]+)""",
             """User Name:\s+({user}[^@\s]+).+?Service Name:\s+({service_name}\S+).+?Client Address:\s+({src_ip}[a-fA-F:\d.]+).+?Failure Code:\s+({result_code}[^\s]+)""",
             """Service Name:\s+({dest_host}\S+\$)\s""",
	     """Ticket Options:\s+({ticket_options}[^\s]+)""",
	     """Ticket Encryption Type:\s+({ticket_encryption_type}[^\s]+)"""
           ]
}
```