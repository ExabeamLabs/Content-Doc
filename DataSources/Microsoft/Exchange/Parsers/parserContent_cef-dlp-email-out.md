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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """\srt=({time}\d{1,100})""",
    """\sdvc=({host}[\d.]+)""",
    """\sdvchost=({host}[^\s]*)""",
    """\scs6=({orig_user}.+?)\s{1,100}\w+=""",
    """\ssuser=({user_email}.+?)\s{1,100}\w+=""",
    """\sduser=({external_address}[^\s]+)""",
    """\sduser=[^@]+@({external_domain}[^\s;]+)""",
    """\sduser=({recipient}[^\s@;,"]+@[^\s@;,"]+)""",
    """\sduser=({recipients}.+?)\s{1,100}\w+=""",
    """\smsg=({subject}.+?)\s{1,100}\w+=""",
    """\|RECEIVE\|RECEIVE\|.+?in=({bytes}\d{1,100})""",
    """\|SEND\|SEND\|.+?out=({bytes}\d{1,100})""",
    """\seventId=({alert_id}\d{1,100})"""
    """\ssourceServiceName=({alert_name}[^\s]+)""",
    """\ssourceServiceName=({alert_type}[^\s]+)""",
    """CEF([^\|]*\|){6}({alert_severity}[^|]+)""",
    """CEF([^\|]*\|){5}({action}[^|]+)""",
    """({direction}o)""",
    """\scategoryOutcome=(\/)?({outcome}[^\s]*)"""
  ]
  DupFields = [ "orig_user->sender", "orig_user->user" ]
}
```