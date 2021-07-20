#### Parser Content
```Java
{
Name = forefront-epp-cef-alert
  Vendor = Microsoft
  Product = Windows Defender
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "epoch"
  Conditions = [ """|Microsoft|Forefront Endpoint Protection|""" ]
  Fields = [
    """exabeam_EventTime=({eventtime}\d{1,100})""",
    """\|Microsoft\|({host}.+?)\|""",
    """\|Microsoft\|[^|]{1,2000}?\|[^|]{1,2000}?\|[^|]{1,2000}?\|({alert_type}[^\|]{1,2000})\|""",
    """\|Microsoft\|[^|]{1,2000}?\|[^|]{1,2000}?\|[^|]{1,2000}?\|[^|]{1,2000}?\|({alert_severity}[^\|]{1,2000})""",
    """\seventId=({alert_id}[^\s]{1,2000})""",
    """\srt=({time}\d{1,100})""",
    """\scs1=({alert_name}[^\s]{1,2000})""",
    """\sdst=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdhost=({src_host}[^\.\s]{1,2000})""",
    """\sduser=({user}[^\s]{1,2000})""",
    """\sfname=({malware_url}.+?) cs1=""",
    """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdvchost=({host}[^\s]{1,2000})"""
  ]
  DupFields = ["host->dest_host", "malware_url->process_name"]
}
```