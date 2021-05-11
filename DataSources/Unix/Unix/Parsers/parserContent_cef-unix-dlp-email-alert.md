#### Parser Content
```Java
{
Name = cef-unix-dlp-email-alert
  Vendor = Unix
  Product = Unix
  Lms = Splunk
  DataType = "dlp-email-alert"
  TimeFormat = "epoch"
  Conditions = [ """|Unix|Sendmail|""", """|Email """, """ Message|""" ]
  Fields = [
    """\Wrt=({time}\d{1,100})""",
    """\Wdvc=({host}[^\s]+)""",
    """\Wdvchost=({host}[^\s]+)""",
    """CEF:([^\|]*\|){4}({alert_name}[^\|]+)""",
    """CEF:([^\|]*\|){6}({alert_severity}[^\|]+)""",
    """\WeventId=({alert_id}\d{1,100})""",
    """\Wdsn\\=({outcome}[^\s,]+)""",
    """\Wsuser=({sender}[^\s]+)""",
    """\WsourceDnsDomain=({external_domain_sender}[^\s]+)""",
    """\Wduser=\s{0,100}({recipient}[^\s;,"]+)""",
    """\Wduser=\s{0,100}({recipients}[^\s]+)""",
    """\WdestinationDnsDomain=({external_domain_recipient}[^\s]+)""",
    """\Wcn3=({num_recipients}\d{1,100})""",
    """\Wsize\\=({bytes}\d{1,100})""",
    """\Wproto=({protocol}[^\s,]+)"""
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```