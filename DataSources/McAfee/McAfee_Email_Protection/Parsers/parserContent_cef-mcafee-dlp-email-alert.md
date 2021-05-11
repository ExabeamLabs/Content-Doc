#### Parser Content
```Java
{
Name = cef-mcafee-dlp-email-alert
  Vendor = McAfee
  Product = McAfee Email Protection
  Lms = ArcSight
  DataType = "dlp-email-alert"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|McAfee|Secure Internet Gateway|""", """|smtp:Email Delivered|""" ]
  Fields = [
    """CEF:([^\|]*\|){4}({alert_name}[^\|]+)""",
    """\Wrt=({time}\d{1,100})""",
    """\Wdvchost=({host}[\w\-.]+)""",
    """\WeventId=({alert_id}\d{1,100})""",
    """\Wact=({outcome}.+?)\s{1,100}([\w\\]+=|$)""",
    """\Wshost=({src_host}[\w\-.]+)""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]+)""",
    """\WFrom\\=<({sender}[^\s>]+)""",
    """\WFrom\\=<[^@]+@({external_domain_sender}[^\s>]+)""",
    """\Wsize=({bytes}\d{1,100})""",
    """\Wto\\=<({recipients}[^>]+)""",
    """\Wto\\=<({recipient}[^\s>,;]+)""",
    """\Wto\\=<[^@]+@({external_domain_recipient}[^\s>]+)""",
    """\Wsubject\\='({subject}[^']+)""",
    """\Wattachment\(s\)\\='(|({attachments}[^']+))'""",
    """\Wattachment\(s\)\\='(|({attachment}[^,']+)),""",
    """\Wnumber-attachment\(s\)='({num_attachments}\d{1,100})""", 
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```