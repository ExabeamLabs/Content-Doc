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
    """exabeam_EventTime=({eventtime}\d+)""",
    """\|Microsoft\|({host}.+?)\|""",
    """\|Microsoft\|.+?\|.+?\|.+?\|({alert_type}[^\|]+)\|""",
    """\|Microsoft\|.+?\|.+?\|.+?\|.+?\|({alert_severity}[^\|]+)""",
    """\seventId=({alert_id}[^\s]+)""",
    """\srt=({time}\d+)""",
    """\scs1=({alert_name}[^\s]+)""",
    """\sdst=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdhost=({src_host}[^\.\s]+)""",
    """\sduser=({user}[^\s]+)""",
    """\sfname=({malware_url}.+?) cs1=""",
    """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdvchost=({host}[^\s]+)"""
  ]
  DupFields = ["host->dest_host", "malware_url->process_name"]
}
```