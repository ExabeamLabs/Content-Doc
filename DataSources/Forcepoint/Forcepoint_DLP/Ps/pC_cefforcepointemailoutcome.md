#### Parser Content
```Java
{
Name = cef-forcepoint-email-outcome
  Vendor = Forcepoint
  Product = Forcepoint DLP
  Lms = ArcSight
  DataType = "dlp-email-alert"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Forcepoint|AP-EMAIL|""", """|Delivery|Delivery|""" ]
  Fields = [
    """CEF:([^\|]{0,2000}\|){6}({alert_severity}[^\|]{1,2000})""",
    """\Wrt=({time}\d{1,100})""",
    """\Wdvc=({host}[\d.]{1,2000})""",
    """\Wdvchost=({host}[\w\-.]{1,2000})""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wdst=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wact=(|({outcome}\S+))\s""",
    """\WmessageId=({alert_id}\d{1,100})""",
  ]
}
}
```