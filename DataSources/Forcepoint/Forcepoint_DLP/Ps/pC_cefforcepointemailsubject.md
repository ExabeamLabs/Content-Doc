#### Parser Content
```Java
{
Name = cef-forcepoint-email-subject
  Vendor = Forcepoint
  Product = Forcepoint DLP
  Lms = ArcSight
  DataType = "dlp-email-alert"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Forcepoint|AP-EMAIL|""", """|Message|Message|""" ]
  Fields = [
    """CEF:([^\|]{0,2000}\|){6}({alert_severity}[^\|]{1,2000})""",
    """\Wrt=({time}\d{1,100})""",
    """\Wdvc=({host}[\d.]{1,2000})""",
    """\Wdvchost=({host}[\w\-.]{1,2000})""",
    """\Wmsg=\s{0,100}({subject}.+?)\s{1,100}(\w+=|$)""",
    """\Win=({bytes}\d{1,100})""",
    """\Wfname=(|({attachments}.*?))\s{1,100}(\w+=|$)""",
    """\Wfrom="{0,20}([^"@\s]{1,2000}@[^"@\s]{1,2000}|({user_fullname}[^"<@]{1,2000}?))"{0,20}\s{1,100}<({sender}[^\s=@,;>]{1,2000}@[^\s=@,;>]{1,2000})""",
    """\Wsuser=(|({sender}[^\s]{1,2000}))""",
    """\WtrueSrc=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\WmessageId=({alert_id}\d{1,100})""",
    """\Wcc=(|({cc}[^\s]{1,2000}))""",
    """\Wurl="(|({url}[^"]{1,2000}))"""",
  ]


}
```