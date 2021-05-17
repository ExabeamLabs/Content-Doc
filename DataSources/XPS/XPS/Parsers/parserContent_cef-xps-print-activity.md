#### Parser Content
```Java
{
Name = cef-xps-print-activity
    Vendor = XPS
  Product = XPS
    Lms = ArcSight
    DataType = "print-activity"
    TimeFormat = "yyyy-MM-dd\tHH:mm:ss a"
    Conditions = [ """XPS""", """PRINT""" ]
    Fields = [
      """({time}\d{1,100}\-\d{1,100}\-\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100} (PM|pm|AM|am))\t+({host}[^\t]{1,2000})\t+(?:-|({printer_name}[^\t]{1,2000}))\t+(?:-|({user}[^\t]{1,2000}))\t+[^\t]{1,2000}\t+(?:-|({src_host}[^\t]{1,2000}))\t+(?:-|({object}.+?))\t+(\d{1,100}\t+){3}\d{1,100}\.\d{1,100}\s{1,100}.+?\s{1,100}(\d{1,100}\s{1,100}){3}XPS\s{1,100}({activity}PRINT)"""
    ]
    DupFields = [ "printer_name->dest_host" ]
  }
```