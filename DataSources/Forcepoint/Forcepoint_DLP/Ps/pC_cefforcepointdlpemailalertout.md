#### Parser Content
```Java
{
Name = cef-forcepoint-dlp-email-alert-out
  Vendor = Forcepoint
  Product = Forcepoint DLP
  Lms = ArcSight
  DataType = "dlp-email-alert"
  TimeFormat = "epoch"
  Conditions = [ "|Forcepoint|Forcepoint DLP|", "sourceServiceName =", "sourceServiceName =SMTP" ]
  Fields = [
    """\Wrt=({time}\d{1,100})""",
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """\Wdvc=(N\/A|({host}[A-Fa-f:\d.]{1,2000}))""",
    """\Wdvchost=(N\/A|({host}[\w\-.]{1,2000}))""",
    """({host}[\w\-.]{1,2000})\s{1,100}CEF:""",
    """\Wact=({outcome}.+?)(\s\-\s|\s{1,100}[\w\.]{1,2000}=|$)""",
    """\Wduser=(N\/A|({recipient}[^\s;@]{1,2000}@[^\s;@]{1,2000}))""",
    """\Wfname=\s{0,100}({attachment}[^;]{1,2000}?)(;.*?)?\s{0,100}([\w\.]{1,2000}=|$)"""
    """\Wfname=\s{0,100}({attachments}.+?)\s{0,100}([\w\.]{1,2000}=|$)"""
    """\Wmsg=\s{0,100}({subject}.+?)(\s{1,100}\-\s|\s{1,100}[\w\.]{1,2000}=|$)""",
    """\Wcat=({alert_name}.+?)(\s\-\s|\s{1,100}[\w\.]{1,2000}=|$)""",
    """\WsourceServiceName =({alert_type}.+?)\s{1,100}(on |\w+=)""",
    """\WloginName =(?:N\/A|(({domain}[^\\,]{1,2000})\\+)?({user}[^\\\s,]{1,2000}))(\s\-\s|\s{1,100}[\w\.]{1,2000}=|$)""",
    """\WsourceIp=(?:N\/A|({src_ip}[A-Fa-f:\d.]{1,2000}))""",
    """\WseverityType=({alert_severity}[^\s]{1,2000})""",
    """\WsourceHost=(?:N\/A|({src_host}[\w\-.]{1,2000}))""",
    """\WdestinationHosts=(?:N\/A|(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w\-.]{1,2000})))""",
    """\Wsuser=(({domain}[^\\\s,@=]{1,2000})\\+)?({user}[^\\\s,@=]{1,2000})\s{1,100}(\w+=|$)""",
    """\Wsuser=(Executive Inquiry Mailbox|({user_fullname}[^\\\s,@=]{1,2000}?\s{1,100}[^\\,@=]{1,2000}?))\s{1,100}(\w+=|$)""",
    """\Wsuser=({user_lastname}[^\\,=]{1,2000}?),\s{1,100}({user_firstname}[^\\,=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """\Wsuser=({user_email}[^\\\s,@=]{1,2000}?@[^\\\s,@=]{1,2000}?)\s{1,100}(\w+=|$)""",
  ]
  DupFields = [ "recipient->external_address" ]


}
```