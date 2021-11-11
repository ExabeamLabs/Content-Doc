#### Parser Content
```Java
{
Name = cef-dlp-email-out
  Vendor = Microsoft
  Product = Exchange
  Lms = ArcSight
  DataType = "dlp-email-alert"
  TimeFormat = "epoch"
  Conditions = [ "|Microsoft|Exchange Server|", "flexString1=Originating" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """\srt=({time}\d{1,100})""",
    """\sdvc=({host}[\d.]{1,2000})""",
    """\sdvchost=({host}[^\s]{0,2000})""",
    """\scs6=({orig_user}.+?)\s{1,100}\w+=""",
    """\ssuser=({user_email}.+?)\s{1,100}\w+=""",
    """\sduser=({external_address}[^\s]{1,2000})""",
    """\sduser=({recipient}[^\s@;,"]{1,2000}@[^\s@;,"]{1,2000})""",
    """\sduser=({recipients}.+?)\s{1,100}\w+=""",
    """\smsg=({subject}.+?)\s{1,100}\w+=""",
    """\|RECEIVE\|RECEIVE\|.+?in=({bytes}\d{1,100})""",
    """\|SEND\|SEND\|.+?out=({bytes}\d{1,100})""",
    """\seventId=({alert_id}\d{1,100})"""
    """\ssourceServiceName =({alert_name}[^\s]{1,2000})""",
    """\ssourceServiceName =({alert_type}[^\s]{1,2000})""",
    """CEF([^\|]{0,2000}\|){6}({alert_severity}[^|]{1,2000})""",
    """CEF([^\|]{0,2000}\|){5}({action}[^|]{1,2000})""",
    """({direction}o)""",
    """\scategoryOutcome=(\/)?({outcome}[^\s]{0,2000})"""
  ]
  DupFields = [ "orig_user->sender", "orig_user->user" ]
}
}
```