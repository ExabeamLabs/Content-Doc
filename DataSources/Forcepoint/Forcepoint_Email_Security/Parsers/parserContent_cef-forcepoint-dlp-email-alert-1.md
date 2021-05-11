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
    """\Wmsg=({subject}[^=]+?)\s{1,100}\w+=""",
    """\Wmsg=\[({subject}[^\]]+)""",
    """\Win=({bytes}\d{1,100})""",
    """\Wrt=({time}\d{1,100})""",
    """\WtrueSrc=({src_ip}[a-fA-F\d.:]+)""",
    """exabeam_host=({host}[^\s]+)""",
    """\Wdvc=(ConnectorIP|({host}[a-fA-F\d.:]+))""",
    """\Wdvchost=({host}[^\s]+)""",
    """\WmessageId=({alert_id}[^\s]+)""",
    """\|Forcepoint\|Email Security\|[^\|]*\|({alert_name}[^\|]*)\|({alert_type}[^\|]*)\|({alert_severity}[^\|]*)\|""",
    """suser=({sender}[^@=]+?@({external_domain_sender}[^\s>]+?))(>)?(\s|\s{0,100}$)""",
    """\Wsuser=\s{0,100}([^<]+<)?(<)?({sender}[^@=>]+?@({external_domain_sender}[^@=>]+?))(>)?(\s{1,100}\w+=|\s{0,100}$)""",
    """duser=({recipient}[^@=]+?@({external_domain_recipient}[^\s>]+?))(>)?(\s|\s{0,100}$)""",
    """\Wduser=\s{0,100}([^<]+<)?(<)?({recipient}[^@=>]+?@({external_domain_recipient}[^@=>]+?))(>)?(\s{1,100}\w+=|\s{0,100}$)""",
    """ad.fnameAndfileHash=({attachments}[^|]+?)\s{0,100}\|\s{0,100}({file_hash}[^|\s]+)""",
    """ad.cc=\s{0,100}(Email_in_CC|({recipients}[^=]+))\s{1,100}[\w.\-]+="""
  ]
}
```