#### Parser Content
```Java
{
Name = mobileiron-security-alert
  Vendor = MobileIron
  Product = MobileIron
  Lms = Direct
  DataType = "alert"
  TimeFormat = "epoch_sec"
  Conditions = [ """CEF:""", """|Mobile Iron|""", """deviceSeverity=""", """dtz=""" ]
  Fields = [
    """ start=({time}\d+) """,
    """ eventId=({alert_id}\d+)""",
    """ cat=({alert_name}[^\s]+) """,
    """ suser=({user}.+?)\s+\w+=""",
    """ act=({action}.+?)\s+\w+=""",
    """ platform\\=({os}.+?)(\}|\w+=)""",
    """ dvc=({host}.+?) """,
    """ agt=({src_ip}.+?) """,
    """ act=({alert_name}.+?)\s+\w+=""",
    """ cat=({alert_type}.+?)\s+\w+=""",
    """ cs1=({additional_info}.+?)\s+\w+=""",
    """ cs3=\{({src_host}.+?)\}\s+\w+=""",
  ]
}
```