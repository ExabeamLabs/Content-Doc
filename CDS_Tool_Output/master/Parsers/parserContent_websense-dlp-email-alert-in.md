#### Parser Content
```Java
{
Name = websense-dlp-email-alert-in
  Vendor = Websense ESG
  Lms = Direct
  DataType = "dlp-email-alert"
  TimeFormat = "epoch"
  Conditions = [ """|Websense|ESG|""", """|Message|Message|""", """dvc=""", """msg=""" ]
  Fields = [
    """({host}[\w\-.]+)\s+CEF:""",
    """dvc=({host}[a-fA-F:\d.]+)""",
    """dvchost=({host}[\w\-.]+)""",
    """rt=({time}\d+)""",
    """suser=({sender}\S+)""",
    """suser=({external_address}\S+)""",
    """suser=[^@]+@({external_domain}[^\s;]+)""",
    """duser=({recipients}\S+)""",
    """msg=({subject}.+?)\s*(\w+=|$)""",
    """in=({bytes}\d+)"""
  ]
  DupFields = [ "sender->user" ]
}
```