#### Parser Content
```Java
{
Name = s-skysea-print-activity
  Vendor = SkySea
  Product = ClientView
  Lms = Splunk
  DataType = "print-activity"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ ",????????????," ]
  Fields = [
    """({host}[\w\-.]+),\d+,""",
    """^([^\,]*\,){2}({src_host}[^\,]+)\,""",
    """^([^\,]*\,){3}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\,""",
    """^([^\,]*\,){5}({user}[^\s,]+)\,""",
    """^([^\,]*\,){7}({time}\d+\/\d+\/\d+ \d+:\d+:\d+)""",
    """^([^\,]*\,){8}({activity}[^\,]+)\,""",
    """^([^\,]*\,){12}\s*({object}[^\,]+?)\s*\,""",
    """^([^\,]*\,){32}(((?:[^,]+)?[\\\/])?({printer_name}[^\\\/,]+?))\,""",
    """^([^\,]*\,){33}({num_pages}\d+)\,""",
    """^([^\,]*\,){60}({file_path}[^\,]+)\,""",
    """^([^\,]*\,){57}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
  ]
}
```