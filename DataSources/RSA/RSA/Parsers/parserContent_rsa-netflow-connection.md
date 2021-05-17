#### Parser Content
```Java
{
Name = rsa-netflow-connection
  Vendor = RSA
  Product = RSA
  Lms = Direct
  DataType = "netflow-connection"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """|flowdata|""", """|RSA|""", """src=""", """dst=""" ]
  Fields = [
	"""exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
        """({time}\w{3}\s\d{2}\s\d{4}\s\d{2}:\d{2}:\d{2})""",
        """src=({src_ip}[^\s]{1,2000})\s"""
        """dst=({dest_ip}[^\s]{1,2000})\s"""
        """spt=({src_port}\d{1,100})\s"""
        """dpt=({dest_port}\d{1,100})\s"""
        """proto=({protocol}[^\s]{1,2000})\s"""
        """InPackets=({packets}\d{1,100})"""
        """FirstSwitched=({time_start}\d{1,100})"""
        """LastSwitched=({time_end}\d{1,100})"""
        """in=({bytes}\d{1,100})"""
  ]
}
```