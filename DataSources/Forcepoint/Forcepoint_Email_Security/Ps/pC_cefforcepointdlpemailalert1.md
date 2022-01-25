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
    """\Wmsg=({subject}[^=]{1,2000}?)\s{1,100}\w+=""",
    """\Wmsg=\[({subject}[^\]]{1,2000})""",
    """\Win=({bytes}\d{1,100})""",
    """\Wrt=({time}\d{1,100})""",
    """\WtrueSrc=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """exabeam_host=({host}[^\s]{1,2000})""",
    """\Wdvc=(ConnectorIP|({host}[a-fA-F\d.:]{1,2000}))""",
    """\Wdvchost=({host}[^\s]{1,2000})""",
    """\WmessageId=({alert_id}[^\s]{1,2000})""",
    """\|Forcepoint\|Email Security\|[^\|]{0,2000}\|({alert_name}[^\|]{0,2000})\|({alert_type}[^\|]{0,2000})\|({alert_severity}[^\|]{0,2000})\|""",
    """suser=({sender}[^@=]{1,2000}?@({external_domain_sender}[^\s>]{1,2000}?))(>)?(\s|\s{0,100}$)""",
    """\Wsuser=\s{0,100}([^<]{1,2000}<)?(<)?({sender}[^@=>]{1,2000}?@({external_domain_sender}[^@=>]{1,2000}?))(>)?(\s{1,100}\w+=|\s{0,100}$)""",
    """duser=({recipient}[^@=]{1,2000}?@({external_domain_recipient}[^\s>]{1,2000}?))(>)?(\s|\s{0,100}$)""",
    """\Wduser=\s{0,100}([^<]{1,2000}<)?(<)?({recipient}[^@=>]{1,2000}?@({external_domain_recipient}[^@=>]{1,2000}?))(>)?(\s{1,100}\w+=|\s{0,100}$)""",
    """ad.fnameAndfileHash=({attachments}[^|]{1,2000}?)\s{0,100}\|\s{0,100}({file_hash}[^|\s]{1,2000})""",
    """ad.cc=\s{0,100}(Email_in_CC|({recipients}[^=]{1,2000}))\s{1,100}[\w.\-]{1,2000}="""
  ]


}
```