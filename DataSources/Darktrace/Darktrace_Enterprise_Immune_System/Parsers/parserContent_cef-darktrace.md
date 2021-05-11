#### Parser Content
```Java
{
Name = cef-darktrace
   Vendor = Darktrace
   Product = Darktrace Enterprise Immune System
   Lms = Direct
   DataType = "alert"
   TimeFormat = "epoch"
   Conditions = [ "CEF:","|Darktrace|DCIP|" ]
   Fields = [
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """exabeam_host=([^=]+?@\s{0,100})?({host}[\w.-]+)""",
      """exabeam_EventTime=({time}\d{1,100})""",
      """\sdst=({dest_ip}[^\s]*)\sdvchost""",
      """\|\d{1,100}\|({alert_type}[^\/]*)\/""",
      """\/({alert_name}[^\|]*)\|\d""",
      """\sdvc=(0.0.0.0|({src_ip}[^\s]*))\s""",
      """\d{2}\s({host}[^\s]*)\s<""",
      """\|externalId=({alert_id}\d{1,100})\s""",
      """\|Darktrace\|DCIP\|[^\|]+\|({category_id}\d{1,100})\|""",
      """\sdvchost=(|({src_host}[^\s]*))\s""",
      """\|({alert_severity}\d{1,100})\|external"""
      ]
 }
```