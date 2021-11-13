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
    """CEF:([^\|]{0,2000}\|){4}({alert_name}[^\|]{1,2000})""",
    """\Wrt=({time}\d{1,100})""",
    """\Wdvchost=({host}[\w\-.]{1,2000})""",
    """\WeventId=({alert_id}\d{1,100})""",
    """\Wact=({outcome}.+?)\s{1,100}([\w\\]{1,2000}=|$)""",
    """\Wshost=({src_host}[\w\-.]{1,2000})""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\WFrom\\=<({sender}[^\s>]{1,2000})""",
    """\Wsize=({bytes}\d{1,100})""",
    """\Wto\\=<({recipients}[^>]{1,2000})""",
    """\Wto\\=<({recipient}[^\s>,;]{1,2000})""",
    """\Wsubject\\='({subject}[^']{1,2000})""",
    """\Wattachment\(s\)\\='(|({attachments}[^']{1,2000}))'""",
    """\Wattachment\(s\)\\='(|({attachment}[^,']{1,2000})),""",
    """\Wnumber-attachment\(s\)='({num_attachments}\d{1,100})""", 
  ]
  DupFields = [ "alert_name->alert_type" ]


}
```