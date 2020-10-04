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

{
  Name = unix-dlp-email-out
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ sSMTP[""", """]: Sent mail""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """Sent mail for ({sender}[^\s]+)""",
    """outbytes=({bytes}\d+)""",
    """uid=({email_id}[^\s]+)""",
    """username=({user}[^\s]+)"""
  ]
}
```