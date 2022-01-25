#### Parser Content
```Java
{
Name = sendmail-email-from
  Vendor = Unix
  Product = Unix Sendmail
  Lms = Direct
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """ TRANSMIT[""", """from=<""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}(\+|\-)\d\d:\d\d)\s{1,100}({host}\W+\S+)\s{1,100}TRANSMIT\[.*?\]:\s{0,100}({alert_id}[^:]{1,2000}?)\s{0,100}:""",
    """\sfrom=<({sender}[^@]{1,2000}?@({external_domain_sender}.+?))>""",
    """\ssize=({bytes}\d{1,100})""",
    """\snrcpts=({num_recipients}\d{1,100})""",
    """\sproto=({protocol}[^,]{1,2000})""",
    """\srelay=({dest_host}[\w\-.]{1,2000})\s{0,100}\[({dest_ip}[a-fA-F:\d.]{1,2000})""",
  ]


}
```