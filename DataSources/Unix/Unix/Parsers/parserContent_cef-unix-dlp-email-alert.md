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
    """\Wdvc=({host}[^\s]{1,2000})""",
    """\Wdvchost=({host}[^\s]{1,2000})""",
    """CEF:([^\|]{0,2000}\|){4}({alert_name}[^\|]{1,2000})""",
    """CEF:([^\|]{0,2000}\|){6}({alert_severity}[^\|]{1,2000})""",
    """\WeventId=({alert_id}\d{1,100})""",
    """\Wdsn\\=({outcome}[^\s,]{1,2000})""",
    """\Wsuser=({sender}[^\s]{1,2000})""",
    """\WsourceDnsDomain=({external_domain_sender}[^\s]{1,2000})""",
    """\Wduser=\s{0,100}({recipient}[^\s;,"]{1,2000})""",
    """\Wduser=\s{0,100}({recipients}[^\s]{1,2000})""",
    """\WdestinationDnsDomain=({external_domain_recipient}[^\s]{1,2000})""",
    """\Wcn3=({num_recipients}\d{1,100})""",
    """\Wsize\\=({bytes}\d{1,100})""",
    """\Wproto=({protocol}[^\s,]{1,2000})"""
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```