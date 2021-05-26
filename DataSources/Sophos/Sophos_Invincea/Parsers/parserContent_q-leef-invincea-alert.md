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
	"""exabeam_host=(.+?@\s{0,100})?({host}[^\s]{1,2000})""",
	"""\s\d{1,2} \d\d:\d\d:\d\d\s{1,100}({host}[^\s]{1,2000})""",
	"""devTime1=({time}\w+ \d{1,100} \d{4} \d\d:\d\d:\d\d)""",
	"""LEEF[^|]{1,2000}?\|([^|]{1,2000}\|){4}({alert_name}[^|]{1,2000})""",
	"""sev=({alert_severity}\d{1,100})""",
	"""usrName=(?:|({user}.+?))\s{1,100}\w+=""",
	"""\ssrc=({src_ip}[^\s]{1,2000})""",
	"""\ssrcHostName=({src_host}[^\s]{1,2000})""",
	"""\|externalId=({alert_id}\d{1,100})""",
	"""\surl=(?:|({malware_url}.+?))\s{1,100}\w+="""
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```