#### Parser Content
```Java
{
Name = varonis-dlp-alert-2
  Vendor = Varonis
  Product = Data Security Platform
  Lms = Splunk
  DataType = "dlp-alert"
  TimeFormat = "MM/dd/yyyy hh:mm:ss a"
  Conditions = [ """| Varonis alert: ""","""| Alert details: """ ]
  Fields = [
    """\|\sEvent Time:\s({time}\d{1,2}\/\d{1,2}\/\d\d\d\d\s\d{1,2}:\d{1,2}:\d{1,2}\s((?i)am|pm))""",
    """\|\sDevice hostname:\s(|({host}[^\|]{1,2000}?))\s\|""",
    """\|\sActing Object:\s((Exchange Online|({domain}[^\\\|]{1,2000}?))(\s\([^\)]{1,2000}\))?\\{1,20})?(S\-(\d{1,100}\-){6}\d{1,20}|other|({user_fullname}[^\|]{1,2000}?))\s((\-|\()[^\|]{1,2000})?\|""",
    """\|\sActing Object SAM Account Name:\s(({user_sid}S\-(\d{1,100}\-){6}\d{1,20})|({user}[^\|\s]{1,2000}?))\s\|""",
    """\|\sDevice IP address:\s({dest_ip}[a-fA-F\d:\.]{1,2000}?)\s\|""",
    """\|\sRule Name:\s({alert_name}[^\|]{1,2000}?)\s\|""",
    """\|\sEvent Type:\s({alert_type}[^\|]{1,2000}?)\s\|""",
    """\|\sSeverity:\s({alert_severity}\d{1,5})\s\|""",
    """\|\sRule ID:\s({alert_id}\d{1,20})\s\|""",
    """\|\sEvent Status:\s({outcome}[^\|]{1,2000}?)\s\|""",
    """\|\sRule Description:\s({additional_info}[^\|]{1,2000}?)\s\|""",
    """\|\sPath:\s({additional_info}[^\|]{1,2000}?)\s\|"""
  ]


}
```