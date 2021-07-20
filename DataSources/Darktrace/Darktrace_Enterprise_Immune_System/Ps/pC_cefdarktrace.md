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
      """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
      """exabeam_EventTime=({time}\d{1,100})""",
      """\sdst=({dest_ip}[^\s]{0,2000})\sdvchost""",
      """\|\d{1,100}\|({alert_type}[^\/]{0,2000})\/""",
      """\/({alert_name}[^\|]{0,2000})\|\d""",
      """\sdvc=(0.0.0.0|({src_ip}[^\s]{0,2000}))\s""",
      """\d{2}\s({host}[^\s]{0,2000})\s<""",
      """\|externalId=({alert_id}\d{1,100})\s""",
      """\|Darktrace\|DCIP\|[^\|]{1,2000}\|({category_id}\d{1,100})\|""",
      """\sdvchost=(|({src_host}[^\s]{0,2000}))\s""",
      """\|({alert_severity}\d{1,100})\|external"""
      ]
 }
```