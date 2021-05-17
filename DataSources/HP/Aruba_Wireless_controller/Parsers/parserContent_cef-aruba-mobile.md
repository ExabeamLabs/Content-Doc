#### Parser Content
```Java
{
Name = cef-aruba-mobile
  Vendor = HP
  Product = Aruba Wireless controller
  Source = Mobility Controller
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "epoch"
  Conditions = ["""|Aruba Networks""" , """Mobility Controller""" , """catdt=Wireless Security"""]
  Fields = [
     """rt=({time}[^\s]{1,2000})""",
     """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
     """Mobility Controller\|?.*?\|.*?\|({src_host}[^\|]{1,2000})\|"""
     """cat=({alert_name}.+?)\srt""",
     """catdt=({alert_type}[^\s]{1,2000})""",
     """\s{1,100}at=({activity}[^\s]{1,2000})""",
  ]
}
```