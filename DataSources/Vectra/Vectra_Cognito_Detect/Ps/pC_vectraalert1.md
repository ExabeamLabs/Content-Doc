#### Parser Content
```Java
{
Name = vectra-alert-1
  Vendor = Vectra
  Product = Vectra Cognito Detect
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """vectra_standard_account_detection""", """: DETECT """, """detection@"""]
  Fields = [
	"""({host}[\w.\-]{1,2000})\s{1,100}vectra_standard_account_detection""",
	"""\saccount="({user_email}[^"]{1,2000})"""",
	"""\sthreat="({alert_severity}[^"]{1,2000})""",
	"""\stype="({alert_name}[^"]{1,2000})""",
	"""\scategory="({category}[^"]{1,2000})""",
	"""\sDesetinationIP="(0\.0\.0\.0|({dest_ip}[a-fA-F\d.:]{1,2000}))""",
	"""\sdest_port="({dest_port}\d{1,100})""",
	"""\sBytesSent="({bytes_out}\d{1,100})""",
	"""\sBytesRcvd="({bytes_in}\d{1,100})""",
	"""\sUTCTimeStart="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)"""
  ]
}
```