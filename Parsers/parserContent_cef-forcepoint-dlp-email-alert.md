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
    """\Wrt=({time}\d+)""",
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """\Wdvc=(N\/A|({host}[A-Fa-f:\d.]+))""",
    """\Wdvchost=(N\/A|({host}[\w\-.]+))""",
    """({host}[\w\-.]+)\s+CEF:""",
    """\Wact=({outcome}.+?)(\s\-\s|\s+[\w\.]+=|$)""",
    """\Wduser=(N\/A|({recipient}[^\s;@]+@({external_domain}[^\s;@]+)))""",
    """\Wfname=\s*({attachment}[^;]+?)(;.*?)?\s*([\w\.]+=|$)"""
    """\Wfname=\s*({attachments}.+?)\s*([\w\.]+=|$)"""
    """\Wmsg=\s*({subject}.+?)(\s+\-\s|\s+[\w\.]+=|$)""",
    """\Wcat=({alert_name}.+?)(\s\-\s|\s+[\w\.]+=|$)""",
    """\WsourceServiceName=({alert_type}.+?)\s+(on |\w+=)""",
    """\WloginName=(?:N\/A|(({domain}[^\\,]+)\\+)?({user}[^\\\s,]+))(\s\-\s|\s+[\w\.]+=|$)""",
    """\WsourceIp=(?:N\/A|({src_ip}[A-Fa-f:\d.]+))""",
    """\WseverityType=({alert_severity}[^\s]+)""",
    """\WsourceHost=(?:N\/A|({src_host}[\w\-.]+))""",
    """\WdestinationHosts=(?:N\/A|(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w\-.]+)))""",
    """\Wsuser=(({domain}[^\\\s,@=]+)\\+)?({user}[^\\\s,@=]+)\s+(\w+=|$)""",
    """\Wsuser=(Executive Inquiry Mailbox|({user_fullname}[^\\\s,@=]+?\s+[^\\,@=]+?))\s+(\w+=|$)""",
    """\Wsuser=({user_lastname}[^\\,=]+?),\s+({user_firstname}[^\\,=]+?)\s+(\w+=|$)""",
    """\Wsuser=({user_email}[^\\\s,@=]+?@[^\\\s,@=]+?)\s+(\w+=|$)""",
  ]
  DupFields = [ "recipient->external_address" ]
}
```