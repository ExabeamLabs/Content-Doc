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
    """({time}\d+\-\d+\-\d+\s+\d+:\-\s*\d+:\d+ (PM|pm|AM|am))\s+({host}[^\s]+)\s+(?:-|({printer_name}[^\s]+))\s+(?:-|({user}[^\s]+))\s+\S+\s+(?:-|({src_host}[^\s]+))\s+(?:-|({object}.+?))\s+(\d+\s+){3}\d+\.\d+\s+.+?\s+(\d+\s+){3}PostScript  ({activity}PRINT)"""
  ]
  DupFields = [ "printer_name->dest_host" ]
}
```