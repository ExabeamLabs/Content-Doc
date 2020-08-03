#### Parser Content
```Java
{
Name = cef-siteminder-auth-failed
  Vendor = SiteMinder
  Product = SiteMinder
  Lms = ArcSight
  DataType = "authentication-failed"
  TimeFormat = "epoch"
  Conditions = [ """|Computer Associates|""", """SiteMinder|""", """categoryOutcome=/Failure""" ]
  Fields = [
    """rt=({time}\d+)""",
    """dvc=({host}[a-fA-F:\d.]+)""",
    """dvchost=({host}[\w\-.]+)""",
    """shost=({src_host}[\w\-.]+)""",
    """src=({src_ip}[a-fA-F:\d.]+)""",
    """dhost=({dest_host}[\w\-.]+)""",
    """dst=({dest_ip}[a-fA-F:\d.]+)""",
    """duser=(uid\\=)?({user}[^=\\\s,]+)""",
    """suser=({user}\S+)"""
  ]
}
```