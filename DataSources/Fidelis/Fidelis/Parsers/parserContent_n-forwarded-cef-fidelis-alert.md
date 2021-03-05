#### Parser Content
```Java
{
Name = n-forwarded-cef-fidelis-alert
  Vendor = Fidelis
  Product = Fidelis
  Lms = NitroCefSyslog
  DataType = "alert"
  TimeFormat = "epoch"
  Conditions = [ """|McAfee|ESM|""", """|429-""" ]
  Fields = [
	"""\srt=({time}\d+)""",
	"""\|McAfee\|ESM\|.+?\|.+?\|({alert_name}.+?)\|""",
	"""\|McAfee\|ESM\|.+?\|.+?\|[^|]*\s({alert_type}[^\s]+)\s({alert_name}(FSS_|Malware|DNS).+?)\|""",
	"""\|McAfee\|ESM\|.+?\|.+?\|.+?\|({alert_severity}.+?)\|""",
	"""\sdeviceTranslatedAddress=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
	"""\sexternalId=({alert_id}\d+)""",
	"""\sshost=({src_host}[^\s|]+)""",
	"""\sspt=({src_port}\d+)""",
	"""\sdpt=({dest_port}\d+)""",
	"""\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
	"""\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
	"""\ssntdom=(?:<n\/a>|({malware_url}.+?))\s+\w+="""
          ]
}
```