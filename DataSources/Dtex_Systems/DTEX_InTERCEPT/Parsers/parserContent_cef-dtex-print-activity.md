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
    """\Wstart=({time}\d{1,100})""",
    """\WDevice_Name=(({domain}[^\\]+)\\+)?({host}[^\\\s]+)""",
    """\WUser_Name=(({domain}[^\\]+)\\+)?({user}[^\\\s]+)\s""",
    """Printer_Details=\{.*?"Name":\s{0,100}"({printer_name}[^"\s]+)""",
    """Printer_Pages=({num_pages}\d{1,100})""",
    """Source_File_Name=({object}.+?)\s{0,100}(\w+=|$)""",
    """reason=.+?\[({num_pages}\d{1,100})\spage\(s\)\]\[({bytes}\d{1,100})\sbytes""",
    """([^\|]*\|){5}({activity}[^\|]+)""",
  ]
  DupFields = [ "host->src_host" ]
}
```