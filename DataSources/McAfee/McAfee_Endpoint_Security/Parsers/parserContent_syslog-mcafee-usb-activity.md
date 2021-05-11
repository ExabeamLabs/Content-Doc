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
        """"EPO[^"]+"\|(".*?"\||[^|]*\|)\s{0,100}"({time}\d{1,100}\/\d{1,100}\/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM))""",
        """"EPO[^"]+"\|(".*?"\||[^|]*\|){2}\s{0,100}"({host}[^"]+)""",
        """"EPO[^"]+"\|(".*?"\||[^|]*\|){3}\s{0,100}"(({domain}[^\\/"]+)[\\\/])?({user}[^\\\/"]+)"""",
        """"EPO[^"]+"\|(".*?"\||[^|]*\|){5}\s{0,100}"({device_type}[^"]+)"""",
        """"EPO[^"]+"\|(".*?"\||[^|]*\|){6}\s{0,100}"({device_type}[^"]+)"""",
        """"EPO[^"]+"\|(".*?"\||[^|]*\|){5}\s{0,100}"({activity_details}[^"]+)""""
      ]
    }
```