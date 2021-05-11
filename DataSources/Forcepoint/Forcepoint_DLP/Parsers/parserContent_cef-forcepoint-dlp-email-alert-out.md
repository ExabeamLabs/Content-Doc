#### Parser Content
```Java
{
Name = cef-forcepoint-dlp-email-alert-out
  Vendor = Forcepoint
  Product = Forcepoint DLP
  Lms = ArcSight
  DataType = "dlp-email-alert"
  TimeFormat = "epoch"
  Conditions = [ "|Forcepoint|Forcepoint DLP|", "sourceServiceName=", "sourceServiceName=SMTP" ]
  Fields = [
    """\Wrt=({time}\d{1,100})""",
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """\Wdvc=(N\/A|({host}[A-Fa-f:\d.]+))""",
    """\Wdvchost=(N\/A|({host}[\w\-.]+))""",
    """({host}[\w\-.]+)\s{1,100}CEF:""",
    """\Wact=({outcome}.+?)(\s\-\s|\s{1,100}[\w\.]+=|$)""",
    """\Wduser=(N\/A|({recipient}[^\s;@]+@({external_domain}[^\s;@]+)))""",
    """\Wfname=\s{0,100}({attachment}[^;]+?)(;.*?)?\s{0,100}([\w\.]+=|$)"""
    """\Wfname=\s{0,100}({attachments}.+?)\s{0,100}([\w\.]+=|$)"""
    """\Wmsg=\s{0,100}({subject}.+?)(\s{1,100}\-\s|\s{1,100}[\w\.]+=|$)""",
    """\Wcat=({alert_name}.+?)(\s\-\s|\s{1,100}[\w\.]+=|$)""",
    """\WsourceServiceName=({alert_type}.+?)\s{1,100}(on |\w+=)""",
    """\WloginName=(?:N\/A|(({domain}[^\\,]+)\\+)?({user}[^\\\s,]+))(\s\-\s|\s{1,100}[\w\.]+=|$)""",
    """\WsourceIp=(?:N\/A|({src_ip}[A-Fa-f:\d.]+))""",
    """\WseverityType=({alert_severity}[^\s]+)""",
    """\WsourceHost=(?:N\/A|({src_host}[\w\-.]+))""",
    """\WdestinationHosts=(?:N\/A|(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w\-.]+)))""",
    """\Wsuser=(({domain}[^\\\s,@=]+)\\+)?({user}[^\\\s,@=]+)\s{1,100}(\w+=|$)""",
    """\Wsuser=(Executive Inquiry Mailbox|({user_fullname}[^\\\s,@=]+?\s{1,100}[^\\,@=]+?))\s{1,100}(\w+=|$)""",
    """\Wsuser=({user_lastname}[^\\,=]+?),\s{1,100}({user_firstname}[^\\,=]+?)\s{1,100}(\w+=|$)""",
    """\Wsuser=({user_email}[^\\\s,@=]+?@[^\\\s,@=]+?)\s{1,100}(\w+=|$)""",
  ]
  DupFields = [ "recipient->external_address" ]
}
```