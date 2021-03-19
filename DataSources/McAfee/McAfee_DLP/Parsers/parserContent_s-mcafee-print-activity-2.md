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
     """^([^|]*\|){29}({app}[^|]+)""",
     """^([^|]*\|){14}({dest_ip}[a-fA-F:\d.]+)""",
     """^([^|]*\|){12}({event_name}[^|]+)""",
     """^([^|]*\|){15}({host}[^|]+)""",
     """^([^|]*\|){17}({object}[^|]+)""",
     """^([^|]*\|){11}({printer_name}[^|]+)""",
     """^([^|]*\|){2}({time}[^|]+)""",
     """^([^|]*\|){20}(({domain}[^\\]+)\\*)?({user}[^|]+)"""
  ]
}
```