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
    """exabeam_host=({host}[\w.\-]+)""",
    """lastActivityTime=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\w+\s+\d+\s+\d\d:\d\d:\d\d\s+({host}[^\s]+)""",
    """\|Cyphort\|.+?\|.+?\|.+?\|({alert_type}.+?)\|""",
    """\|Cyphort\|.+?\|.+?\|.+?\|({alert_name}.+?)\|""",
    """\|Cyphort\|.+?\|.+?\|.+?\|.+?\|({alert_severity}.+?)\|""",
    """\seventId=({alert_id}\d+)""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sfileName=({file_name}.+?)\s+\w+=""",
    """\surl=({malware_url}[^\r\n]+)\s+""",
    """\smalwareSeverity=({alert_severity}.+?)\s+\w+=""",
    """\smalwareCategory=({alert_type}.+?)\s+\w+="""
  ]
  DupFields = ["file_name->process_name"]
}
```