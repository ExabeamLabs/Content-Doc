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
    """({host}[\w\-\.]{1,2000})\s{0,100}CEF:""",
    """\Wdvc=({host}\S+)\s{0,100}(\w+=|$)""",
    """\Wdvchost=({host}\S+)\s{0,100}(\w+=|$)""",
    """\Wrt=({time}\d{1,100})""",
    """CEF.+?([^|]{0,2000}\|){5}({alert_name}[^|]{1,2000})""",
    """\WeventId=({alert_id}\d{1,100})""",
    """\Wshost=({src_host}\S+)\s{0,100}(\w+=|$)""",
    """\Wdhost=({dest_host}\S+)\s{0,100}(\w+=|$)""",
    """\Wsrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Wdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Wsuser="?(({domain}[^\s\\"]{1,2000})\\+)?(\?|({user}[^\\\s"]{1,2000}))"?\s{0,100}(\w+=|$)""",
    """\Wduser="?(({domain}[^\s\\"]{1,2000})\\+)?(\?|({db_user}[^\\\s"]{1,2000}))"?\s{0,100}(\w+=|$)""",
    """\WdestinationServiceName=({service_name}.+?)\s{0,100}(\w+=|$)""",
    """\Wcs1=({alert_type}.+?)\s{0,100}(\w+=|$)""",
    """\Wcs2=({server_group}.+?)\s{0,100}(\w+=|$)""",
    """\Wcs5=(|({database_name}.+?))\s{0,100}(\w+=|$)"""
  ]
  DupFields = [ "db_user->account" ]
}
```