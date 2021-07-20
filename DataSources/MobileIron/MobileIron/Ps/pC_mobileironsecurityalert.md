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
    """ start=({time}\d{1,100}) """,
    """ eventId=({alert_id}\d{1,100})""",
    """ cat=({alert_name}[^\s]{1,2000}) """,
    """ suser=({user}.+?)\s{1,100}\w+=""",
    """ act=({action}.+?)\s{1,100}\w+=""",
    """ platform\\=({os}.+?)(\}|\w+=)""",
    """ dvc=({host}.+?) """,
    """ agt=({src_ip}.+?) """,
    """ act=({alert_name}.+?)\s{1,100}\w+=""",
    """ cat=({alert_type}.+?)\s{1,100}\w+=""",
    """ cs1=({additional_info}.+?)\s{1,100}\w+=""",
    """ cs3=\{({src_host}.+?)\}\s{1,100}\w+=""",
  ]
}
```