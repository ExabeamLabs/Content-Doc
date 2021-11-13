#### Parser Content
```Java
{
Name = cisco-adc-web-activity
  Vendor = Cisco
  Product = Cisco ADC
  Lms = Syslog
  DataType = "web-activity"
  TimeFormat = "dd/MMM/yyyy:HH:mm:ss"
  Conditions = [ """] """, """ [""", """[ADC_APP]""" ]
  Fields = [
    """\[({host}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\]\[\d{1,100}\]\[\S+\]\[\]\s({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\s\[({time}\d{1,100}\/\w+\/\d\d\d\d:\d\d:\d\d:\d\d)\s{1,100}\+\d{1,100}\]\s({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\s[\S]{0,2000}\s\s({dest_translated_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})?\s({dest_translated_port}\d{1,100})?\s"({uri_path}\S+)"\s"({method}\S+)?\s\S*\s({protocol}\S+)?"\s"({full_url}\S+)?"\s"({user_agent}.*)?"""",
  ]


}
```