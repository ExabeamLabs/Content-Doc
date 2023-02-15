#### Parser Content
```Java
{
Name = cef-netskope-dlp-alert-4
  Vendor = Netskope
  Product = Security Cloud
  Lms = Direct
  DataType = "alert"
  TimeFormat = "epoch_sec"
  Conditions = [ """CEF:0|Netskope|""", """|DLP|""" ]
  Fields = [
    """timestamp=({time}\d{10,13})""",
    """\|DLP\|({alert_name}[^\|]{1,2000})\|({alert_severity}[^\|]{1,2000})\|""",
    """({alert_type}DLP)""",
    """dlpFile=({file_name}[^=]{1,2000}?)\s\w+=""",
    """dlpIncidentId=({alert_id}\d{1,2000}?)\s""",
    """dst=({dest_ip}[A-Fa-f\d.:]{1,2000})\s"""
    """fsize=({bytes}\d{1,2000})\s"""
    """requestClientApplication=(null|({app}[^=]{1,2000}?))\s\w+=""",
    """md5=({md5}[^=]{1,2000}?)\s\w+=""",
    """sha256=({sha256}[^=]{1,2000}?)\s\w+=""",
    """suser=(({user_email}[^@=\s]{1,2000}@[^@=\s\.]{1,2000}\.[^=\s]{1,2000})|({user}[^=@\\\/\s]{1,2000}))""",
    """url=({target}[^~]{1,2000}?)\s("|$)""",
  ]


}
```