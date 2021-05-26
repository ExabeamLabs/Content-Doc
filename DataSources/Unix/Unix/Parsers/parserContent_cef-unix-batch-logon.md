#### Parser Content
```Java
{
Name = cef-unix-batch-logon
  Vendor = Unix
  Product = Unix
  Lms = ArcSight
  DataType = "batch-logon"
  TimeFormat = "epoch"
  Conditions = [ """|Unix|Unix|""", """|session opened|""", """cs1=su """, """ by (uid""" ]
  Fields = [
    """\srt=({time}\d{1,100})""",
    """\sduser=({user}.+?)\s{1,100}\w+=""",
    """ dst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """ dhost=({dest_host}[^\s]{1,2000})""",
  ]
  DupFields = [ "dest_host->host"]
}
```