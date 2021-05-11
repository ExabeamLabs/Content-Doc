#### Parser Content
```Java
{
Name = cef-proofpoint-dlp-alert-1
  Vendor = Proofpoint
  Product = Proofpoint Enterprise Protection
  Lms = ArcSight
  DataType = "dlp-alert"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|ProofPoint|""", """|Email Quarantine Out|""" ]
  Fields = [
    """\Wrt=({time}\d{1,100})""",
    """\Wdvchost=({host}.+?)\s{0,100}(\w+=|$)""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]+)""",
    """\Wshost=({src_host}.+?)\s{0,100}(\w+=|$)""",
    """\Wsuser=({sender}.+?)\s{0,100}(\w+=|$)""",
    """\Wdst=({dest_ip}[A-Fa-f:\d.]+)""",
    """\Wdhost=({dest_host}.+?)\s{0,100}(\w+=|$)""",
    """\Wduser=({recipients}.+?)\s{0,100}(\w+=|$)""",
    """\Wduser=({recipient}[^,\s]+)""",
    """\Wcs1=({email_id}.+?)\s{0,100}(\w+=|$)""",
    """\WflexString2=({alert_name}.+?)\s{0,100}(\w+=|$)""",
    """({alert_type}Email Quarantine)""",
    """\WeventId=({alert_id}\d{1,100})"""
  ]
  DupFields = [ "sender->user_email", "recipient->target" ]
}
```