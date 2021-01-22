#### Parser Content
```Java
{
Name = cef-aruba-mobile
  Vendor = Aruba Networks
  Source = Mobility Controller
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "epoch"
  Conditions = ["""|Aruba Networks""" , """Mobility Controller""" , """catdt=Wireless Security"""]
  Fields = [
     """rt=({time}[^\s]+)""",
     """exabeam_host=([^=]+@\s*)?({host}\S+)""",
     """Mobility Controller\|?.*?\|.*?\|({src_host}[^\|]+)\|"""
     """cat=({alert_name}.+?)\srt""",
     """catdt=({alert_type}[^\s]+)""",
     """\s+at=({activity}[^\s]+)""",
  ]
}
```