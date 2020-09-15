#### Parser Content
```Java
{
Name = cef-syslog-guardium-db-alert-1
  Vendor = IBM
  Product = Infosphere Guardium
  Lms = Direct
  DataType = "database-alert"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """|IBM|Guardium|10.18|""", """cs5Label=DB Name""" ]
  Fields = [
    """({host}[\w\-\.]+)\s*CEF:""",
    """\Wdvc=({host}\S+)\s*(\w+=|$)""",
    """\Wdvchost=({host}\S+)\s*(\w+=|$)""",
    """\Wrt=({time}\d+)""",
    """CEF.+?([^|]*\|){5}({alert_name}[^|]+)""",
    """\WeventId=({alert_id}\d+)""",
    """\Wshost=({src_host}\S+)\s*(\w+=|$)""",
    """\Wdhost=({dest_host}\S+)\s*(\w+=|$)""",
    """\Wsrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Wdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Wsuser="?(({domain}[^\s\\"]+)\\+)?(\?|({user}[^\\\s"]+))"?\s*(\w+=|$)""",
    """\Wduser="?(({domain}[^\s\\"]+)\\+)?(\?|({db_user}[^\\\s"]+))"?\s*(\w+=|$)""",
    """\WdestinationServiceName=({service_name}.+?)\s*(\w+=|$)""",
    """\Wcs1=({alert_type}.+?)\s*(\w+=|$)""",
    """\Wcs2=({server_group}.+?)\s*(\w+=|$)""",
    """\Wcs5=(|({database_name}.+?))\s*(\w+=|$)"""
  ]
  DupFields = [ "db_user->account" ]
}
```