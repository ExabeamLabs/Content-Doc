#### Parser Content
```Java
{
Name = n-forwarded-cef-fidelis-alert
  Vendor = Fidelis
  Product = Fidelis XPS
  Lms = NitroCefSyslog
  DataType = "alert"
  TimeFormat = "epoch"
  Conditions = [ """|McAfee|ESM|""", """|429-""" ]
  Fields = [
	"""\srt=({time}\d{1,100})""",
	"""\|McAfee\|ESM\|[^|]+?\|[^|]+?\|({alert_name}.+?)\|""",
	"""\|McAfee\|ESM\|[^|]+?\|[^|]+?\|[^|]*\s({alert_type}[^\s]+)\s({alert_name}(FSS_|Malware|DNS).+?)\|""",
	"""\|McAfee\|ESM\|[^|]+?\|[^|]+?\|[^|]+?\|({alert_severity}.+?)\|""",
	"""\sdeviceTranslatedAddress=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
	"""\sexternalId=({alert_id}\d{1,100})""",
	"""\sshost=({src_host}[^\s|]+)""",
	"""\sspt=({src_port}\d{1,100})""",
	"""\sdpt=({dest_port}\d{1,100})""",
	"""\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
	"""\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
	"""\ssntdom=(?:<n\/a>|({malware_url}.+?))\s{1,100}\w+="""
          ]
}
```