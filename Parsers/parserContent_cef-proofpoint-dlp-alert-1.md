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
    """\Wrt=({time}\d+)""",
    """\Wdvchost=({host}.+?)\s*(\w+=|$)""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]+)""",
    """\Wshost=({src_host}.+?)\s*(\w+=|$)""",
    """\Wsuser=({sender}.+?)\s*(\w+=|$)""",
    """\Wdst=({dest_ip}[A-Fa-f:\d.]+)""",
    """\Wdhost=({dest_host}.+?)\s*(\w+=|$)""",
    """\Wduser=({recipients}.+?)\s*(\w+=|$)""",
    """\Wduser=({recipient}[^,\s]+)""",
    """\Wcs1=({email_id}.+?)\s*(\w+=|$)""",
    """\WflexString2=({alert_name}.+?)\s*(\w+=|$)""",
    """({alert_type}Email Quarantine)""",
    """\WeventId=({alert_id}\d+)"""
  ]
  DupFields = [ "sender->user_email", "recipient->target" ]
}
```