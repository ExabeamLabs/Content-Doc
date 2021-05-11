#### Parser Content
```Java
{
Name = websense-dlp-email-alert-in
  Vendor = Forcepoint
  Product = Websense ESG
  Lms = Direct
  DataType = "dlp-email-alert"
  TimeFormat = "epoch"
  Conditions = [ """|Websense|ESG|""", """|Message|Message|""", """dvc=""", """msg=""" ]
  Fields = [
    """({host}[\w\-.]+)\s{1,100}CEF:""",
    """dvc=({host}[a-fA-F:\d.]+)""",
    """dvchost=({host}[\w\-.]+)""",
    """rt=({time}\d{1,100})""",
    """suser=({sender}\S+)""",
    """suser=({external_address}\S+)""",
    """suser=[^@]+@({external_domain}[^\s;]+)""",
    """duser=({recipients}\S+)""",
    """msg=({subject}.+?)\s{0,100}(\w+=|$)""",
    """in=({bytes}\d{1,100})"""
  ]
  DupFields = [ "sender->user" ]
}
```