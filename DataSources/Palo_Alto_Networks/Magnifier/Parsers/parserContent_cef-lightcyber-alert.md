#### Parser Content
```Java
{
Name = cef-lightcyber-alert
  Vendor = Palo Alto Networks
  Product = Magnifier
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """|LightCyber|Magna|""" ]
  Fields = [
    """start=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """\|LightCyber\|Magna\|[^|]{1,2000}?\|[^|]{1,2000}?\|({alert_name}[^|]{1,2000}?)\|""",
    """\|LightCyber\|Magna\|[^|]{1,2000}?\|[^|]{1,2000}?\|[^|]{1,2000}?\|({alert_severity}[^|]{1,2000}?)\|""",
    """\sexternalId=({alert_id}\d{1,100})""",
    """\sshost=(?: |({src_host}.+?))\s{0,100}\w+=""",
    """\ssuser=(?: |({user}.+?))\s{0,100}\w+=""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\scs1=(?: |({alert_type}.+?))\s{0,100}\w+=""",
    """\smsg=(?: |({additional_info}.+?))\s{0,100}\w+=""",
    """\sfilePath=(?: |({malware_url}.+?))\s{0,100}\w+=""",
    """\|LightCyber\|Magna\|[^|]{1,2000}?\|[^|]{1,2000}?\|({alert_type}[^|]{1,2000}?)\|[^"]{1,2000}?\s{1,100}cs2=({alert_name}[^=]{1,2000}?)\s{1,100}fileHash="""
  ]
  DupFields = ["host->dest_host", "malware_url->process_name"]
}
```