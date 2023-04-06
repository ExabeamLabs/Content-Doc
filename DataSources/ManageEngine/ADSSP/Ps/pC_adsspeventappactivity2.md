#### Parser Content
```Java
{
Name = adssp-event-app-activity-2
  DataType = "app-activity"
  Conditions= [ """CEF:0|ManageEngine|ADSSP|""", """dvchost""", """DATE_TIME""", """ACTION_NAME\=Enrollment""", """[STATUS\=Success]""" ]

adssp-events = {
  Vendor = ManageEngine
  Product = ADSSP
  Lms = Direct
  TimeFormat = "epoch"
  Fields = [
    """TIME\\?=({time}\d{10,13})""",
    """dvchost=({host}[\w\-.]{1,2000})""",
    """LOGIN NAME\\?=(({user_email}[^@"]{1,2000}@[^"\.]{1,2000}.[^"]{1,2000})|({user}[^\s\]]{1,2000}))""",
    """DOMAIN NAME\\?=(-|({domain}[^\]]{1,2000}))""",
    """IP\\?=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """ACTION_NAME\\?=(-|({event_name}[^\]]{1,2000}))""",
    """STATUS\\?=({additional_info}[^\]]{1,2000})""",
    """({app}ADSSP)"""
  ]
 
}
```