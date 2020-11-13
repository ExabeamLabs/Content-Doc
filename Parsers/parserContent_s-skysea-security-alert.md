#### Parser Content
```Java
{
Name = s-skysea-security-alert
  Vendor = SkySea
  Product = ClientView
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ ",想定外TCP通信," ]
  Fields = [
    """exabeam_raw=({host}[^\,]+)\,""",
    """^([^\,]*\,){2}({src_host}[^\,]+)\,""",
    """^([^\,]*\,){3}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\,""",
    """^([^\,]*\,){5}(SYSTEM|({user}[^\,]+))\,""",
    """^([^\,]*\,){7}({time}\d+\/\d+\/\d+ \d+:\d+:\d+)""",
    """^([^\,]*\,){68}({process}({directory}(?:(\w+:)*([\\\/]+[^\\\/"]+)+)?[\\\/]+)({process_name}[^\,\\\/]+))\,""",
    """^([^\,]*\,){69}({md5}[^\,]+)\,""",
    """^([^\,]*\,){70}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\,""",
    """^([^\,]*\,){71}({dest_port}\d+)\,""",
    """^([^\,]*\,){73}({bytes_out}\d+)\,""",
    """^([^\,]*\,){74}({bytes_in}\d+)\,""",
    """^([^\,]*\,){8}({alert_name}[^\,]+)\,""",
    """^([^\,]*\,){72}({additional_info}[^\,]+)\,""",
  ]
  DupFields = [ "directory->process_directory" ]
}
```