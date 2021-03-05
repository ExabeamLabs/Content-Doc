#### Parser Content
```Java
{
Name = cef-darktrace
   Vendor = Darktrace
   Product = Darktrace
   Lms = Direct
   DataType = "alert"
   TimeFormat = "epoch"
   Conditions = [ "CEF:","|Darktrace|DCIP|" ]
   Fields = [
      """exabeam_EventTime=({time}\d+)""",
      """\sdst=({dest_ip}[^\s]*)\sdvchost""",
      """\d{3}\|({alert_type}[^\/]*)\/""",
      """\/({alert_name}[^\|]*)\|\d""",
      """\sdvc=({src_ip}[^\s]*)\s""",
      """\d{2}\s({host}[^\s]*)\s<""",
      """\|externalId=({alert_id}\d{6})\s""",
      """\sdvchost=({src_host}[^\s]*)\s""",
      """\|({alert_severity}\d{1})\|external"""
      ]
 }
```