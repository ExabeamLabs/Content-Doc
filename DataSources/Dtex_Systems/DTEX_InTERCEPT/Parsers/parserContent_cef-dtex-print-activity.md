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
    """\WDevice_Name=(({domain}[^\\]{1,2000})\\+)?({host}[^\\\s]{1,2000})""",
    """\WUser_Name=(({domain}[^\\]{1,2000})\\+)?({user}[^\\\s]{1,2000})\s""",
    """Printer_Details=\{.*?"Name":\s{0,100}"({printer_name}[^"\s]{1,2000})""",
    """Printer_Pages=({num_pages}\d{1,100})""",
    """Source_File_Name=({object}.+?)\s{0,100}(\w+=|$)""",
    """reason=.+?\[({num_pages}\d{1,100})\spage\(s\)\]\[({bytes}\d{1,100})\sbytes""",
    """([^\|]{0,2000}\|){5}({activity}[^\|]{1,2000})""",
  ]
  DupFields = [ "host->src_host" ]
}
```