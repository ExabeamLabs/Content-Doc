#### Parser Content
```Java
{
Name = cef-forcepoint-email-spam-score
  Vendor = Forcepoint
  Product = Forcepoint DLP
  Lms = ArcSight
  DataType = "dlp-email-alert"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Forcepoint|AP-EMAIL|""", """|Policy|Clean|""" ]
  Fields = [
    """CEF:([^\|]{0,2000}\|){6}({alert_severity}[^\|]{1,2000})""",
    """\Wrt=({time}\d{1,100})""",
    """\Wdvc=({host}[\d.]{1,2000})""",
    """\Wdvchost=({host}[\w\-.]{1,2000})""",
    """\Win=({bytes}\d{1,100})""",
    """\Wduser=({recipient}[^\s=,;]{1,2000})""",
    """\WdeviceDirection=(|({direction}.+?))\s{1,100}(\w+=|$)""",
    """\WhybridSpamScore=({spam_score}[\+\-]\d{1,100})""",
    """\Wact=({action}\d{1,100})""",
    """\WmessageId=({alert_id}\d{1,100})""",
  ]
}
}
```