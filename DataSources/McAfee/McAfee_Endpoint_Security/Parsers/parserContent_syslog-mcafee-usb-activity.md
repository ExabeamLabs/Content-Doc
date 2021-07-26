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
        """"EPO[^"]{1,2000}"\|(".*?"\||[^|]{0,2000}\|)\s{0,100}"({time}\d{1,100}\/\d{1,100}\/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM))""",
        """"EPO[^"]{1,2000}"\|(".*?"\||[^|]{0,2000}\|){2}\s{0,100}"({host}[^"]{1,2000})""",
        """"EPO[^"]{1,2000}"\|(".*?"\||[^|]{0,2000}\|){3}\s{0,100}"(({domain}[^\\/"]{1,2000})[\\\/])?({user}[^\\\/"]{1,2000})"""",
        """"EPO[^"]{1,2000}"\|(".*?"\||[^|]{0,2000}\|){5}\s{0,100}"({device_type}[^"]{1,2000})"""",
        """"EPO[^"]{1,2000}"\|(".*?"\||[^|]{0,2000}\|){6}\s{0,100}"({device_type}[^"]{1,2000})"""",
        """"EPO[^"]{1,2000}"\|(".*?"\||[^|]{0,2000}\|){5}\s{0,100}"({activity_details}[^"]{1,2000})""""
      ]
    }
```