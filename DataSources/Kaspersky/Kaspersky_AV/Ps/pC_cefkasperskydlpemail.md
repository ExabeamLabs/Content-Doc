#### Parser Content
```Java
{
Name = cef-kaspersky-dlp-email
  Vendor = Kaspersky
  Product = Kaspersky AV
  Lms = Direct
  DataType = "dlp-email-alert"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """Kaspersky|KSMG""", """destinationDnsDomain=""" ]
  Fields = [
    """shost=({dest_host}[^\s]{1,2000})"""
    """\srt=({time}\d{1,100})""",
    """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdvchost=({host}[^\s]{1,2000})""",
    """\ssuser=({sender}[^\s]{1,2000})\s{1,100}(\w+=|$)""",
    """\sduser=({recipient}[^\s]{1,2000})\s{1,100}(\w+=|$)""",
    """fsize=({bytes}\d{1,100})""",
    """src=({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """msg=\w+\s{1,100}"{1,20}({attachment}[^"]{1,2000})""",
    ]


}
```