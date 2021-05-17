#### Parser Content
```Java
{
Name = cef-siteminder-auth-successful
  Vendor = SiteMinder
  Product = SiteMinder
  Lms = ArcSight
  DataType = "authentication-successful"
  TimeFormat = "epoch"
  Conditions = [ """|Computer Associates|""", """SiteMinder|""", """categoryOutcome=/Success""" ]
  Fields = [
    """rt=({time}\d{1,100})""",
    """dvc=({host}[a-fA-F:\d.]{1,2000})""",
    """dvchost=({host}[\w\-.]{1,2000})""",
    """shost=({src_host}[\w\-.]{1,2000})""",
    """src=({src_ip}[a-fA-F:\d.]{1,2000})""",
    """dhost=({dest_host}[\w\-.]{1,2000})""",
    """dst=({dest_ip}[a-fA-F:\d.]{1,2000})""",
    """duser=(uid\\=)?({user}[^=\\\s,]{1,2000})""",
    """suser=({user}\S+)"""
  ]
}
```