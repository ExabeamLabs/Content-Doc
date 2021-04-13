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
      """exabeam_host=([^=]+?@\s*)?({host}[\w.-]+)""",
      """exabeam_EventTime=({time}\d+)""",
      """\sdst=({dest_ip}[^\s]*)\sdvchost""",
      """\|\d+\|({alert_type}[^\/]*)\/""",
      """\/({alert_name}[^\|]*)\|\d""",
      """\sdvc=(0.0.0.0|({src_ip}[^\s]*))\s""",
      """\d{2}\s({host}[^\s]*)\s<""",
      """\|externalId=({alert_id}\d+)\s""",
      """\|Darktrace\|DCIP\|[^\|]+\|({category_id}\d+)\|""",
      """\sdvchost=(|({src_host}[^\s]*))\s""",
      """\|({alert_severity}\d+)\|external"""
      ]
 }
```