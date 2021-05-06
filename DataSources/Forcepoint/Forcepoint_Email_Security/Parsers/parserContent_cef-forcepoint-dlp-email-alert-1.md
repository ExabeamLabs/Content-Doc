#### Parser Content
```Java
{
Name = cef-forcepoint-dlp-email-alert-1
  Vendor = Forcepoint
  Product = Forcepoint Email Security
  Lms = ArcSight
  DataType = "dlp-email-alert"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Forcepoint|Email Security|""", """msg=""" ]
  Fields = [
    """\Wmsg=({subject}[^=]+?)\s+\w+=""",
    """\Wmsg=\[({subject}[^\]]+)""",
    """\Win=({bytes}\d+)""",
    """\Wrt=({time}\d+)""",
    """\WtrueSrc=({src_ip}[a-fA-F\d.:]+)""",
    """exabeam_host=({host}[^\s]+)""",
    """\Wdvc=(ConnectorIP|({host}[a-fA-F\d.:]+))""",
    """\Wdvchost=({host}[^\s]+)""",
    """\WmessageId=({alert_id}[^\s]+)""",
    """\|Forcepoint\|Email Security\|[^\|]*\|({alert_name}[^\|]*)\|({alert_type}[^\|]*)\|({alert_severity}[^\|]*)\|""",
    """suser=({sender}[^@=]+?@({external_domain_sender}[^\s>]+?))(>)?(\s|\s*$)""",
    """\Wsuser=\s*([^<]+<)?(<)?({sender}[^@=>]+?@({external_domain_sender}[^@=>]+?))(>)?(\s+\w+=|\s*$)""",
    """duser=({recipient}[^@=]+?@({external_domain_recipient}[^\s>]+?))(>)?(\s|\s*$)""",
    """\Wduser=\s*([^<]+<)?(<)?({recipient}[^@=>]+?@({external_domain_recipient}[^@=>]+?))(>)?(\s+\w+=|\s*$)""",
    """ad.fnameAndfileHash=({attachments}[^|]+?)\s*\|\s*({file_hash}[^|\s]+)""",
    """ad.cc=\s*(Email_in_CC|({recipients}[^=]+))\s+[\w.\-]+="""
  ]
}
```