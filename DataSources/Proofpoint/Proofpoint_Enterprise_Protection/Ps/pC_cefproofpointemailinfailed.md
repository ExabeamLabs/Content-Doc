#### Parser Content
```Java
{
Name = cef-proofpoint-email-in-failed
  Conditions = [ """CEF:""", """|ProofPoint|""", """|Failed Email Delivery In|""" ]

cef-proofpoint-email = {
  Vendor = Proofpoint
  Product = Proofpoint Enterprise Protection
  Lms = ArcSight
  DataType = "dlp-alert"
  TimeFormat = "epoch"
  Fields = [
    """\Wrt=({time}\d{1,100})""",
    """\Wdvchost=({host}.+?)\s{0,100}(\w+=|$)""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wshost=({src_host}.+?)\s{0,100}(\w+=|$)""",
    """\Wsuser=({sender}.+?)\s{0,100}(\w+=|$)""",
    """\Wdst=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wdhost=({dest_host}.+?)\s{0,100}(\w+=|$)""",
    """\Wduser=({recipients}.+?)\s{0,100}(\w+=|$)""",
    """\Wduser=({recipient}[^@]{1,2000}@[^\s,]{1,2000})""",
    """\Wcn1=({bytes}\d{1,100})""",
    """\Wcs5=({attachments}.+?)\s{0,100}(\w+=|$)""",
    """\Wcs5="?({attachment}[^,"]{1,2000}?)("|,|\s{0,100}(\w+=|$))""",
    """\Wcs6=({subject}.+?)\s{0,100}(\w+=|$)""",
    """\Wdproc=({email_id}.+?)\s{0,100}(\w+=|$)""",
    """\WeventId=({alert_id}\d{1,100})""",
    """CEF:([^\|]{0,2000}\|){5}({alert_name}[^\|]{1,2000})"""
  ]
  DupFields = [ "attachment->file_name", "alert_name->alert_type" 
}
```