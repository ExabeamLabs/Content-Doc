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
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """\srt=({time}\d+)""",
    """\sdvc=({host}[\d.]+)""",
    """\sdvchost=({host}[^\s]*)""",
    """\scs6=({orig_user}.+?)\s+\w+=""",
    """\ssuser=({email_user}.+?)\s+\w+=""",
    """\sduser=({external_address}[^\s]+)""",
    """\sduser=[^@]+@({external_domain}[^\s;]+)""",
    """\sduser=({recipient}[^\s@;,"]+@[^\s@;,"]+)""",
    """\sduser=({recipients}.+?)\s+\w+=""",
    """\smsg=({subject}.+?)\s+\w+=""",
    """\|RECEIVE\|RECEIVE\|.+?in=({bytes}\d+)""",
    """\|SEND\|SEND\|.+?out=({bytes}\d+)""",
    """\seventId=({alert_id}\d+)"""
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