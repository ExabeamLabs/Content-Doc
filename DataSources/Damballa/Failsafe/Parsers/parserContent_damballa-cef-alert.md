#### Parser Content
```Java
{
Name = damballa-cef-alert
  Vendor = Damballa
  Product = Failsafe
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "epoch"
  Conditions = [ "CEF:", """|Damballa|Failsafe""" ]
  Fields = [
    """exabeam_EventTime=({eventtime}\d{1,100})""",
    """\|Damballa\|[^|]{1,2000}?\|[^|]{1,2000}?\|[^|]{1,2000}?\|({alert_name}[^\|]{1,2000}?)\|""",
    """\|Damballa\|[^|]{1,2000}?\|[^|]{1,2000}?\|[^|]{1,2000}?\|[^|]{1,2000}?\|({alert_severity}[^\|]{1,2000})""",
    """\seventId=({alert_id}[^\s]{1,2000})""",
    """\srt=({time}\d{1,100})""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sshost=({src_host}[^\.\s]{1,2000})""",
    """\sdhost=({dest_host}[^\.\s]{1,2000})""",
    """\srequest=({malware_url}.+?)\s{1,100}\w+=""",
    """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdvchost=({host}[^\s]{1,2000})""",
    """\sreason=({alert_type}[^\s]{1,2000})"""
  ]
}
```