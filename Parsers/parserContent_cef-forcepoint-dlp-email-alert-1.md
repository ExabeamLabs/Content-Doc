#### Parser Content
```Java
{
Name = cef-forcepoint-dlp-email-alert-1
  Vendor = Forcepoint
  Product = Forcepoint DLP
  Lms = ArcSight
  DataType = "dlp-email-alert"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Forcepoint|Email Security|""" ]
  Fields = [
    """\Wmsg=\[({subject}[^\]]+)""",
    """\Win=({bytes}\d+)""",
    """\Wrt=({time}\d+)""",
    """\WtrueSrc=({src_ip}[a-fA-F\d.:]+)""",
    """\Wdvc=({host}[a-fA-F\d.:]+)""",
    """\Wdvchost=(|({host}.+?))(\s+\w+=|\s*$)""",
    """\WmessageId=(|({alert_id}.+?))(\s+\w+=|\s*$)""",
    """\|Forcepoint\|Email Security\|[^\|]*\|({alert_name}[^\|]*)\|({alert_type}[^\|]*)\|({alert_severity}[^\|]*)\|""",
    """\Wfrom=\s*([^<]+<)?(<)?({sender}[^@=>]+?@({external_domain_sender}[^@=>]+?))(>)?(\s+\w+=|\s*$)"""
    """\Wto=\s*([^<]+<)?(<)?({recipient}[^@=>]+?@({external_domain_recipient}[^@=>]+?))(>)?(\s+\w+=|\s*$)"""
  ]
}
```