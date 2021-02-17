#### Parser Content
```Java
{
Name = cef-unix-dlp-email-alert
  Vendor = Unix
  Lms = Splunk
  DataType = "dlp-email-alert"
  TimeFormat = "epoch"
  Conditions = [ """|Unix|Sendmail|""", """|Email """, """ Message|""" ]
  Fields = [
    """\Wrt=({time}\d+)""",
    """\Wdvc=({host}[^\s]+)""",
    """\Wdvchost=({host}[^\s]+)""",
    """CEF:([^\|]*\|){4}({alert_name}[^\|]+)""",
    """CEF:([^\|]*\|){6}({alert_severity}[^\|]+)""",
    """\WeventId=({alert_id}\d+)""",
    """\Wdsn\\=({outcome}[^\s,]+)""",
    """\Wsuser=({sender}[^\s]+)""",
    """\WsourceDnsDomain=({external_domain_sender}[^\s]+)""",
    """\Wduser=\s*({recipient}[^\s;,"]+)""",
    """\Wduser=\s*({recipients}[^\s]+)""",
    """\WdestinationDnsDomain=({external_domain_recipient}[^\s]+)""",
    """\Wcn3=({num_recipients}\d+)""",
    """\Wsize\\=({bytes}\d+)""",
    """\Wproto=({protocol}[^\s,]+)"""
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```