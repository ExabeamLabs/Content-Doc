#### Parser Content
```Java
{
Name = cef-forcepoint-dlp-email-alert
  Vendor = Forcepoint
  Product = Forcepoint DLP
  Lms = ArcSight
  DataType = "dlp-email-alert"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Forcepoint|AP-EMAIL|""", """|Message|Message|""" ]
  Fields = [
    """\Wrt=({time}\d{1,100})""",
    """\Wdvc=({host}[\d.]{1,2000})""",
    """\Wdvchost=({host}[\w\-.]{1,2000})""",
    """\WeventId=({alert_id}\d{1,100})""",
    """\Wmsg=\s{0,100}({subject}.+?)\s{1,100}(\w+=|$)""",
    """\Wout=({bytes}\d{1,100})""",
    """\Wsuser=({sender}[^\s]{1,2000})""",
    """\Wsuser=({external_address}[^\s]{1,2000}).+?cs6=Inbound""",
    """\Wcs6=Inbound.+?suser=({external_address}[^\s]{1,2000})""",
    """\WsourceDnsDomain=({external_domain}[^\s]{1,2000}).+?cs6=Inbound""",
    """\Wcs6=Inbound.+?sourceDnsDomain=({external_domain}[^\s]{1,2000})""",
    """\Wduser=({recipients}.+?)\s{1,100}(\w+=|$)""",
    """\Wduser=({recipient}[^\s,]{1,2000})""",
    """\Wduser=({external_address}[^\s,]{1,2000}).+?cs6=Outbound""",
    """\Wcs6=Outbound.+?duser=({external_address}[^\s,]{1,2000})""",
    """\WdestinationDnsDomain=({external_domain}[^\s]{1,2000}).+?cs6=Outbound""",
    """\Wcs6=Outbound.+?destinationDnsDomain=({external_domain}[^\s]{1,2000})""",
    """\Wfname=({attachments}.*?)\s{1,100}(\w+=|$)""",
    """\Wcs6=({direction}.+?)\s{1,100}(\w+=|$)""",
    """CEF:([^\|]{0,2000}\|){6}({alert_severity}[^\|]{1,2000})""",
  ]
}
```