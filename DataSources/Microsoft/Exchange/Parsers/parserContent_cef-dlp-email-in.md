#### Parser Content
```Java
{
Name = cef-dlp-email-in
  Vendor = Microsoft
  Product = Exchange
  Lms = ArcSight
  DataType = "dlp-email-alert"
  TimeFormat = "epoch"
  Conditions = [ "|Microsoft|Exchange Server|", "flexString1=Incoming" ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """\srt=({time}\d{1,100})""",
    """\sdvc=({host}[\d.]+)""",
    """\sdvchost=\[?({host}[^\s\]]*)""",
    """\scs6=({return_path}.+?)\s{1,100}\w+=""",
    """\ssuser=({sender}.+?)\s{1,100}\w+=""",
    """\ssuser=({external_address}.+?)\s{1,100}\w+=""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sduser=({orig_user}[^\s]+)""",
    """\ssuser=[^@]+@({external_domain}[^\s;]+)""",
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
    """({direction}i)""",
    """\scategoryOutcome=(\/)?({outcome}[^\s]*)"""
  ]
  DupFields = [ "orig_user->user" ]
}
```