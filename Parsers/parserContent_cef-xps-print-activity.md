#### Parser Content
```Java
{
Name = cef-xps-print-activity
    Vendor = XPS
    Lms = ArcSight
    DataType = "print-activity"
    TimeFormat = "yyyy-MM-dd\tHH:mm:ss a"
    Conditions = [ """XPS""", """PRINT""" ]
    Fields = [
      """({time}\d+\-\d+\-\d+\s+\d+:\d+:\d+ (PM|pm|AM|am))\t+({host}[^\t]+)\t+(?:-|({printer_name}[^\t]+))\t+(?:-|({user}[^\t]+))\t+[^\t]+\t+(?:-|({src_host}[^\t]+))\t+(?:-|({object}.+?))\t+(\d+\t+){3}\d+\.\d+\s+.+?\s+(\d+\s+){3}XPS\s+({activity}PRINT)"""
    ]
    DupFields = [ "printer_name->dest_host" ]
  }
```