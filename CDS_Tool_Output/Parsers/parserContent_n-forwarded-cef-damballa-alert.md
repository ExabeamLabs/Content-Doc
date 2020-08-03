#### Parser Content
```Java
{
Name = n-forwarded-cef-damballa-alert
  Vendor = Damballa
  Product = Failsafe
  Lms = NitroCefSyslog
  DataType = "alert"
  TimeFormat = "epoch"
  Conditions = [ "|McAfee|ESM", "|421-" ]
  Fields = [
    """\srt=({time}\d+)""",
    """\|McAfee\|ESM\|.+?\|.+?\|({alert_name}.+?)\|""",
    """\|McAfee\|ESM\|.+?\|.+?\|.+?\|({alert_severity}.+?)\|""",
    """\sdeviceTranslatedAddress=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sexternalId=({alert_id}\d+)""",
    """\sshost=({src_host}[^\s]+)""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\snitroObject_Type=({alert_type}.+?)\s+\w+=""",
    """\snitroURL=({additional_info}.+?)\s+\w+="""
  ]
}
```