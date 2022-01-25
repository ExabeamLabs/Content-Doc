#### Parser Content
```Java
{
Name = cef-proofpoint-dlp-alert-2
  Conditions = [ """CEF:""", """|ProofPoint|FilterLog|""", """|Email Delivery|""" ]

cef-proofpoint-dlp-alert = {
  Vendor = Proofpoint
  Product = Proofpoint Enterprise Protection
  Lms = ArcSight
  DataType = "dlp-alert"
  TimeFormat = "epoch"
  Fields = [
    """\Wrt=({time}\d{1,100})""",
    """\Wdvc=({host}.+?)\s{0,100}(\w+=|$)""",
    """\Wdvchost=({host}.+?)\s{0,100}(\w+=|$)""",
    """CEF:([^\|]{0,2000}\|){5}({alert_name}[^\|]{1,2000})""",
    """\WeventId=({alert_id}\d{1,100})""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wsuser=({sender}.+?)\s{0,100}(\w+=|$)""",
    """\Wduser=({recipients}.+?)\s{0,100}(\w+=|$)""",
    """\Wduser=({recipient}[^=@]{1,2000}@({external_domain_recipient}[^\s,]{1,2000}))""",
    """\Wduser=({external_address}[^\s@,]{1,2000}@({external_domain}[^\s@,]{1,2000}))""",
    """\Wcs5=({attachments}.+?)\s{0,100}(\w+=|$)""",
    """\Wcs5="?({attachment}[^,"]{1,2000}?)("|,|\s{0,100}(\w+=|$))""",
    """\Wcs6=({subject}.+?)\s{0,100}(\w+=|$)""",
    """\Wcn1=({bytes}\d{1,100})""",
    """({outcome}quarantine)""",
  ]
  DupFields = [ "sender->email_user", "sender->user_email", "recipient->target", "attachment->file_name", "alert_name->alert_type" 
}
```