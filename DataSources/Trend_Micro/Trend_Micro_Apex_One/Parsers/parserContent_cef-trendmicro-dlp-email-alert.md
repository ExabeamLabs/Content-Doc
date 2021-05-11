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
    """dvc=({host}[^=]+?)\s{1,100}\w+=""",
    """dvchost=+({host}[^=]+?)\s{1,100}\w+=""",
    """ahost=({host}[^=]+?)\s{1,100}\w+=""",
    """src=({src_ip}[a-fA-F\d.:]+?)\s{1,100}\w+=""",
    """agt=({src_ip}[a-fA-F\d.:]+?)\s{1,100}\w+=""",
    """dst=({dest_ip}[a-fA-F\d.:]+?)\s{1,100}\w+=""",
    """dhost=({dest_host}[^=]+?)\s{1,100}\w+=""",
    """suser=({sender}[^@=]+@[^\s;=]+)""",
    """shost=({recipient}[^@=]+@[^\s;=]+)""",
    """act=(Unknown|({outcome}[^=]+?))\s{1,100}\w+=""",
    """fname=({attachments}[^=]+)\s{1,100}\w+="""
  ]
  DupFields = [ "sender->user_email" ]
}
```