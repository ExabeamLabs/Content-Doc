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
    """\srt=({time}\d{1,100})""",
    """\|McAfee\|ESM\|[^|]{1,2000}?\|[^|]{1,2000}?\|({alert_name}[^|]{1,2000}?)\|""",
    """\|McAfee\|ESM\|[^|]{1,2000}?\|[^|]{1,2000}?\|[^|]{1,2000}?\|({alert_severity}[^|]{1,2000}?)\|""",
    """\sdeviceTranslatedAddress=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sexternalId=({alert_id}\d{1,100})""",
    """\sshost=({src_host}[^\s]{1,2000})""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\snitroObject_Type=({alert_type}.+?)\s{1,100}\w+=""",
    """\snitroURL=({additional_info}.+?)\s{1,100}\w+="""
  ]
}
```