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
    """exabeam_host=({host}[\w.\-]+)""",
    """\|LightCyber\|Magna\|.+?\|.+?\|({alert_name}.+?)\|""",
    """\|LightCyber\|Magna\|.+?\|.+?\|.+?\|({alert_severity}.+?)\|""",
    """\sexternalId=({alert_id}\d+)""",
    """\sshost=(?: |({src_host}.+?))\s*\w+=""",
    """\ssuser=(?: |({user}.+?))\s*\w+=""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\scs1=(?: |({alert_type}.+?))\s*\w+=""",
    """\smsg=(?: |({additional_info}.+?))\s*\w+=""",
    """\sfilePath=(?: |({malware_url}.+?))\s*\w+=""",
    """\|LightCyber\|Magna\|.+?\|.+?\|({alert_type}.+?)\|.+?\s+cs2=({alert_name}.+?)\s+fileHash="""
  ]
  DupFields = ["host->dest_host", "malware_url->process_name"]
}
```