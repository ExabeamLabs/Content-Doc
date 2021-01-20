#### Parser Content
```Java
{
Name = vectra-alert-1
  Vendor = Vectra Networks
  Product = Vectra
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """vectra_standard_account_detection""", """: DETECT """, """detection@"""]
  Fields = [
	"""({host}[\w.\-]+)\s+vectra_standard_account_detection""",
	"""\saccount="({user_email}[^"]+)"""",
	"""\sthreat="({alert_severity}[^"]+)""",
	"""\stype="({alert_name}[^"]+)""",
	"""\scategory="({category}[^"]+)""",
	"""\sDesetinationIP="(0\.0\.0\.0|({dest_ip}[a-fA-F\d.:]+))""",
	"""\sdest_port="({dest_port}\d+)""",
	"""\sBytesSent="({bytes_out}\d+)""",
	"""\sBytesRcvd="({bytes_in}\d+)""",
	"""\sUTCTimeStart="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)"""
  ]
}
```