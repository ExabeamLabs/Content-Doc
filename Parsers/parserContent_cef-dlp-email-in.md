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
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """\srt=({time}\d+)""",
    """\sdvc=({host}[\d.]+)""",
    """\sdvchost=\[?({host}[^\s\]]*)""",
    """\scs6=({return_path}.+?)\s+\w+=""",
    """\ssuser=({sender}.+?)\s+\w+=""",
    """\ssuser=({external_address}.+?)\s+\w+=""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sduser=({orig_user}[^\s]+)""",
    """\ssuser=[^@]+@({external_domain}[^\s;]+)""",
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
    """({direction}i)""",
    """\scategoryOutcome=(\/)?({outcome}[^\s]*)"""
  ]
  DupFields = [ "orig_user->user" ]
}
```