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
      """({time}\d{1,100}\-\d{1,100}\-\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100} (PM|pm|AM|am))\t{1,100}({host}[^\t]{1,2000})\t{1,100}(?:-|({printer_name}[^\t]{1,2000}))\t{1,100}(?:-|({user}[^\t]{1,2000}))\t{1,100}[^\t]{1,2000}\t{1,100}(?:-|({src_host}[^\t]{1,2000}))\t{1,100}(?:-|({object}.+?))\t{1,100}(\d{1,100}\t{1,100}){3}\d{1,100}\.\d{1,100}\s{1,100}.+?\s{1,100}(\d{1,100}\s{1,100}){3}XPS\s{1,100}({activity}PRINT)"""
    ]
    DupFields = [ "printer_name->dest_host" ]
  

}
```