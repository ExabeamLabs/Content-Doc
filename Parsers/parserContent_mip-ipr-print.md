#### Parser Content
```Java
{
Name = mip-ipr-print
  Vendor = MIPS
  Lms = Splunk
  DataType = "print-activity"
  IsHVF = true
  TimeFormat = "yy-MM-dd HH:mm:ss"
  Conditions = [ """ipr_print""", """<custom_condition_cont-7495>""" ]
  Fields = [
    """({time}\d\d-\d\d-\d\d \d\d:\d\d:\d\d)","({user}[^"]+?)","({num_pages}\d+)","({printer_name}\w+)[^"]*?","({src_ip}[^"]+)""""
  ]
}
```