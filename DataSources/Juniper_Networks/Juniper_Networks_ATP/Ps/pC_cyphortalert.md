#### Parser Content
```Java
{
Name = cyphort-alert
  Vendor = Juniper Networks
  Product = Juniper Networks ATP
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = ["|Cyphort|Cortex|"]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """lastActivityTime=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\w+\s{1,100}\d{1,100}\s{1,100}\d\d:\d\d:\d\d\s{1,100}({host}[^\s]{1,2000})""",
    """\|Cyphort\|[^|]{1,2000}?\|[^|]{1,2000}?\|[^|]{1,2000}?\|({alert_type}[^|]{1,2000}?)\|""",
    """\|Cyphort\|[^|]{1,2000}?\|[^|]{1,2000}?\|[^|]{1,2000}?\|({alert_name}[^|]{1,2000}?)\|""",
    """\|Cyphort\|[^|]{1,2000}?\|[^|]{1,2000}?\|[^|]{1,2000}?\|[^|]{1,2000}?\|({alert_severity}[^|]{1,2000}?)\|""",
    """\seventId=({alert_id}\d{1,100})""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sfileName=({file_name}.+?)\s{1,100}\w+=""",
    """\surl=({malware_url}[^\r\n]{1,2000})\s{1,100}""",
    """\smalwareSeverity=({alert_severity}.+?)\s{1,100}\w+=""",
    """\smalwareCategory=({alert_type}.+?)\s{1,100}\w+="""
  ]
  DupFields = ["file_name->process_name"]
}
```