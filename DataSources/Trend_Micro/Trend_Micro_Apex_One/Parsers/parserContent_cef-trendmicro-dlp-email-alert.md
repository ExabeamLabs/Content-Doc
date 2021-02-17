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
    """rt=({time}\d+)""",
    """dvc=({host}[^=]+?)\s+\w+=""",
    """dvchost=+({host}[^=]+?)\s+\w+=""",
    """ahost=({host}[^=]+?)\s+\w+=""",
    """src=({src_ip}[a-fA-F\d.:]+?)\s+\w+=""",
    """agt=({src_ip}[a-fA-F\d.:]+?)\s+\w+=""",
    """dst=({dest_ip}[a-fA-F\d.:]+?)\s+\w+=""",
    """dhost=({dest_host}[^=]+?)\s+\w+=""",
    """suser=({sender}[^@=]+@[^\s;=]+)""",
    """shost=({recipient}[^@=]+@[^\s;=]+)""",
    """act=(Unknown|({outcome}[^=]+?))\s+\w+=""",
    """fname=({attachments}[^=]+)\s+\w+="""
  ]
  DupFields = [ "sender->user_email" ]
}
```