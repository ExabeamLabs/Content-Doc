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
    """shost=({dest_host}[^\s]+)"""
    """\srt=({time}\d{1,100})""",
    """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdvchost=({host}[^\s]+)""",
    """\ssuser=({sender}[^\s]+)\s{1,100}(\w+=|$)""",
    """\sduser=({recipient}[^\s]+)\s{1,100}(\w+=|$)""",
    """ad.externalId=.+?@({external_domain_recipient}[^\s]+)""",
    """\ssuser=.+?@({external_domain_recipient}[^\s]+)""",
    """\sdestinationDnsDomain=({external_domain_sender}[^\s]+)""",
    """fsize=({bytes}\d{1,100})""",
    """src=({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """msg=\w+\s{1,100}"{1,20}({attachment}[^"]+)""",
    ]
}
```