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
	"""exabeam_host=([^=]+@\s*)?({host}\S+)""",
        """({time}\w{3}\s\d{2}\s\d{4}\s\d{2}:\d{2}:\d{2})""",
        """src=({src_ip}[^\s]+)\s"""
        """dst=({dest_ip}[^\s]+)\s"""
        """spt=({src_port}\d+)\s"""
        """dpt=({dest_port}\d+)\s"""
        """proto=({protocol}[^\s]+)\s"""
        """InPackets=({packets}\d+)"""
        """FirstSwitched=({time_start}\d+)"""
        """LastSwitched=({time_end}\d+)"""
        """in=({bytes}\d+)"""
  ]
}
```