#### Parser Content
```Java
{
Name = evntslog-680
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-680"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ """(680)""", """Logon attempt by:""" ]
  Fields = [ 
    """({event_name}Logon attempt)""",
	"""exabeam_host=({host}[\w.\-]+)""",
        """({time}\w+ \d{1,2} [\d:]+ \d+):""",
	"""\d{4}:[\s/]([^/]+)\/Security""",
	"""/Security \(({event_code}680)\)""",
	"""Logon account:\s+({user}[^@]+?)(?:@({domain}[^\s.]+)[^\s]*)?\s+Source Workstation:\s+({dest_host}[^\s.]+)""",
	"""Error Code:\s+({result_code}[^\s]+)"""
  ]
}
```