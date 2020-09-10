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

{
  Name = rsa-vpn-end
  Vendor = RSA
  Product = SecurID
  Lms = Direct
  DataType = "vpn-end"
  TimeFormat = "EEE MMM dd HH:mm:ss z yyyy"
  Conditions = [ """USER_SESSION_REMOVED_TIMEOUT""", """SESSION_ID=""" ]
  Fields = [
    """<\d+>\w+ \d+ \d+:\d+:\d+ ({host}[\w.\-]+)""",
    """\sUSER_AGENT="({user_agent}[^"]+)""",
    """\sSESSION_INACTIVITY_TIMEOUT="({time}\w+ \w+ \d+ \d+:\d+:\d+ \w+ \d\d\d\d)""",
    """\sUSERNAME="({user}[^"]+)""",
    """\sREMOTE_IP="({src_ip}[a-fA-F\d.:]+)""",
    """\sSESSION_ID="({session_id}[^"]+)""",
    """\sREASON="({reason}[^"]+)""",
    """({dest_ip}[a-fA-F\d.:]+)(\s+\S+){2}\s+USER_SESSION_REMOVED_TIMEOUT"""
  ]
  DupFields = ["host->dest_host"]
}
```