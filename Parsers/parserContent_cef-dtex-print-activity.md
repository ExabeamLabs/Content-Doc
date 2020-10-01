#### Parser Content
```Java
{
Name = cef-dtex-print-activity
  Vendor = Dtex Systems
  Product = DTEX InTERCEPT
  Lms = ArcSight
  DataType = "print-activity"
  TimeFormat = "epoch"
  Conditions = [ "CEF:", """|Dtex|""", """|PrintJobActivity|PrintJobIssued|""" ]
  Fields = [
    """\Wstart=({time}\d+)""",
    """\WDevice_Name=(({domain}[^\\]+)\\+)?({host}[^\\\s]+)""",
    """\WUser_Name=(({domain}[^\\]+)\\+)?({user}[^\\\s]+)\s""",
    """Printer_Details=\{.*?"Name":\s*"({printer_name}[^"\s]+)""",
    """Printer_Pages=({num_pages}\d+)""",
    """Source_File_Name=({object}.+?)\s*(\w+=|$)""",
    """reason=.+?\[({num_pages}\d+)\spage\(s\)\]\[({bytes}\d+)\sbytes""",
    """([^\|]*\|){5}({activity}[^\|]+)""",
  ]
  DupFields = [ "host->src_host" ]
}
```