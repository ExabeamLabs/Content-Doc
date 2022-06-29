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
      """\sdst=({dest_ip}[a-fA-F\d:.]{1,2000})\s\w+=""",
      """\|Darktrace\|DCIP\|[^\|]{1,2000}\|\d{1,100}\|({alert_type}[^\/]{0,2000})\/""",
      """\|Darktrace\|DCIP(\|[^\|]{1,2000}){2}[^\/]{0,2000}\/({alert_name}[^\|]{0,2000})\|({alert_severity}\d{1,2})\|""",
      """\s(dvc|src)=(0.0.0.0|({src_ip}[a-fA-F\d:.]{1,2000}))\s""",
      """\d{2}\s({host}[^\s]{0,2000})\s<""",
      """\|externalId=({alert_id}\d{1,100})\s""",
      """\|Darktrace\|DCIP\|[^\|]{1,2000}\|({category_id}\d{1,100})\|""",
      """\s(dvc|s)host=(|({src_host}[^\s]{0,2000}))\s""",
      """\sdhost=(|({dest_host}[^\s]{0,2000}))\s"""
   ]
 

}
```