#### Parser Content
```Java
{
Name = q-leef-invincea-alert
  Vendor = Sophos
  Product = Sophos Invincea
  Lms = QRadar
  DataType = "alert"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ "exabeam_qidName=", "LEEF:1.0|Invincea|" ]
  Fields = [
	"""exabeam_host=(.+?@\s*)?({host}[^\s]+)""",
	"""\s\d{1,2} \d\d:\d\d:\d\d\s+({host}[^\s]+)""",
	"""devTime1=({time}\w+ \d+ \d{4} \d\d:\d\d:\d\d)""",
	"""LEEF.+?\|([^|]+\|){4}({alert_name}[^|]+)""",
	"""sev=({alert_severity}\d+)""",
	"""usrName=(?:|({user}.+?))\s+\w+=""",
	"""\ssrc=({src_ip}[^\s]+)""",
	"""\ssrcHostName=({src_host}[^\s]+)""",
	"""\|externalId=({alert_id}\d+)""",
	"""\surl=(?:|({malware_url}.+?))\s+\w+="""
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```