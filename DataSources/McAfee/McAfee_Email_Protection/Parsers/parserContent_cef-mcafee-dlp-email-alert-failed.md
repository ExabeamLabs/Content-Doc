#### Parser Content
```Java
{
Name = cef-mcafee-dlp-email-alert-failed
  Vendor = McAfee
  Product = McAfee Email Protection
  Lms = ArcSight
  DataType = "dlp-email-alert"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|McAfee|Secure Internet Gateway|""", """|smtp:Email Rejected|""" ]
  Fields = [
    """CEF:([^\|]*\|){4}({alert_name}[^\|]+)""",
    """\Wrt=({time}\d+)""",
    """\Wdvchost=({host}[\w\-.]+)""",
    """\WeventId=({alert_id}\d+)""",
    """\Wact=({outcome}.+?)\s+([\w\\]+=|$)""",
    """\Wshost=({src_host}[\w\-.]+)""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]+)""",
    """\WFrom\\=<({sender}[^\s>]+)""",
    """\WFrom\\=<[^@]+@({external_domain_sender}[^\s>]+)""",
    """\Wsize=(|({bytes}\d+))""",
    """\Wto\\=<(unknown|({recipients}[^>]+))""",
    """\Wto\\=<(unknown|({recipient}[^\s>,;]+))""",
    """\Wto\\=<[^@]+@({external_domain_recipient}[^\s>]+)""",
    """\Wattachment\(s\)\\='(|({attachments}[^']+))'""",
    """\Wattachment\(s\)\\='(|({attachment}[^,']+)),""",
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```