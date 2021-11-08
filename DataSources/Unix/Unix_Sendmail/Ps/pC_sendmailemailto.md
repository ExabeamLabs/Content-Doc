#### Parser Content
```Java
{
Name = sendmail-email-to
  Vendor = Unix
  Product = Unix Sendmail
  Lms = Direct
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """ TRANSMIT[""", """to=<""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}(\+|\-)\d\d:\d\d)\s{1,100}({host}\S+)\s{1,100}TRANSMIT\[.*?\]:\s{0,100}({alert_id}[^:]{1,2000}?)\s{0,100}:""",
    """\sto=<({recipient}[^@]{1,2000}?@.+?)>""",
    """\sto=({recipients}.+?)(,\s{1,100}\[more\])?(,\s{1,100}\w+=|\s{0,100}$)""",
    """\smailer=({protocol}[^,]{1,2000})""",
    """\srelay=({dest_host}[\w\-.]{1,2000})\s{0,100}\[({dest_ip}[a-fA-F:\d.]{1,2000})""",
    """\sdsn=({outcome}[^,]{1,2000})""",
  ]
}
```