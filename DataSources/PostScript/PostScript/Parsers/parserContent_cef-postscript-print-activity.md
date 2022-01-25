#### Parser Content
```Java
{
Name = cef-postscript-print-activity
  Vendor = PostScript
  Product = PostScript
  Lms = ArcSight
  DataType = "print-activity"
  TimeFormat = "yyyy-MM-dd  HH:- mm:ss a"
  Conditions = [ """ PostScript  PRINT""" ]
  Fields = [
    """({time}\d{1,100}\-\d{1,100}\-\d{1,100}\s{1,100}\d{1,100}:\-\s{0,100}\d{1,100}:\d{1,100} (PM|pm|AM|am))\s{1,100}({host}[^\s]{1,2000})\s{1,100}(?:-|({printer_name}[^\s]{1,2000}))\s{1,100}(?:-|({user}[^\s]{1,2000}))\s{1,100}\S+\s{1,100}(?:-|({src_host}[^\s]{1,2000}))\s{1,100}(?:-|({object}.+?))\s{1,100}(\d{1,100}\s{1,100}){3}\d{1,100}\.\d{1,100}\s{1,100}.+?\s{1,100}(\d{1,100}\s{1,100}){3}PostScript  ({activity}PRINT)"""
  ]
  DupFields = [ "printer_name->dest_host" ]
}
```