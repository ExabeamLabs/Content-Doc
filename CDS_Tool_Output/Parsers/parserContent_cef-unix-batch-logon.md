#### Parser Content
```Java
{
Name = cef-unix-batch-logon
  Vendor = Unix
  Lms = ArcSight
  DataType = "batch-logon"
  TimeFormat = "epoch"
  Conditions = [ """|Unix|Unix|""", """|session opened|""", """cs1=su """, """ by (uid""" ]
  Fields = [
    """\srt=({time}\d+)""",
    """\sduser=({user}.+?)\s+\w+=""",
    """ dst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """ dhost=({dest_host}[^\s]+)""",
  ]
  DupFields = [ "dest_host->host"]
}
```