#### Parser Content
```Java
{
Name = s-mcafee-print-activity-2
  Vendor = McAfee
  Product = McAfee DLP
  Lms = Splunk
  DataType = "print-activity"
  TimeFormat = "epoch_sec"
  Conditions = [ """|Log Email Printing|""", """|40301|""" ]  
  Fields = [
     """^([^|]{0,2000}\|){29}({app}[^|]{1,2000})""",
     """^([^|]{0,2000}\|){14}({dest_ip}[a-fA-F:\d.]{1,2000})""",
     """^([^|]{0,2000}\|){12}({event_name}[^|]{1,2000})""",
     """^([^|]{0,2000}\|){15}({host}[^|]{1,2000})""",
     """^([^|]{0,2000}\|){17}({object}[^|]{1,2000})""",
     """^([^|]{0,2000}\|){11}({printer_name}[^|]{1,2000})""",
     """^([^|]{0,2000}\|){2}({time}[^|]{1,2000})""",
     """^([^|]{0,2000}\|){20}(({domain}[^\\]{1,2000})\\*)?({user}[^|]{1,2000})"""
  ]
}
```