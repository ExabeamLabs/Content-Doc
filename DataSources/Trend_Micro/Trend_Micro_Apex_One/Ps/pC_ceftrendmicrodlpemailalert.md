#### Parser Content
```Java
{
Name = cef-trendmicro-dlp-email-alert
  Vendor = Trend Micro
  Product = Trend Micro Apex One
  Lms = ArcSight
  DataType = "dlp-email-alert"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Trend Micro|Apex Central|""", """filePath=SMTP""" ]
  Fields = [
    """rt=({time}\d{1,100})""",
    """dvc=({host}[^=]{1,2000}?)\s{1,100}\w+=""",
    """dvchost=+({host}[^=]{1,2000}?)\s{1,100}\w+=""",
    """ahost=({host}[^=]{1,2000}?)\s{1,100}\w+=""",
    """src=({src_ip}[a-fA-F\d.:]{1,2000}?)\s{1,100}\w+=""",
    """agt=({src_ip}[a-fA-F\d.:]{1,2000}?)\s{1,100}\w+=""",
    """dst=({dest_ip}[a-fA-F\d.:]{1,2000}?)\s{1,100}\w+=""",
    """dhost=({dest_host}[^=]{1,2000}?)\s{1,100}\w+=""",
    """suser=({sender}[^@=]{1,2000}@[^\s;=]{1,2000})""",
    """shost=({recipient}[^@=]{1,2000}@[^\s;=]{1,2000})""",
    """act=(Unknown|({outcome}[^=]{1,2000}?))\s{1,100}\w+=""",
    """fname=({attachments}[^=]{1,2000})\s{1,100}\w+="""
  ]
  DupFields = [ "sender->user_email" ]


}
```