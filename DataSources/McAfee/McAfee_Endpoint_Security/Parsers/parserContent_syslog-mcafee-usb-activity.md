#### Parser Content
```Java
{
Name = syslog-mcafee-usb-activity
      Vendor = McAfee
      Product = McAfee Endpoint Security
      Lms = Direct
      DataType = "usb-activity"
      TimeFormat = "dd/MM/yyyy HH:mm:ss a"
      Conditions = [ """<Custom McAfee USB Conditions>""" ]
      Fields = [
        """"EPO[^"]+"\|(".*?"\||[^|]*\|)\s*"({time}\d+\/\d+\/\d+ \d+:\d+:\d+ (am|AM|pm|PM))""",
        """"EPO[^"]+"\|(".*?"\||[^|]*\|){2}\s*"({host}[^"]+)""",
        """"EPO[^"]+"\|(".*?"\||[^|]*\|){3}\s*"(({domain}[^\\/"]+)[\\\/])?({user}[^\\\/"]+)"""",
        """"EPO[^"]+"\|(".*?"\||[^|]*\|){5}\s*"({device_type}[^"]+)"""",
        """"EPO[^"]+"\|(".*?"\||[^|]*\|){6}\s*"({device_type}[^"]+)"""",
        """"EPO[^"]+"\|(".*?"\||[^|]*\|){5}\s*"({activity_details}[^"]+)""""
      ]
    }
```