#### Parser Content
```Java
{
Name = fireeye-web-activity
  Vendor = FireEye
  Product = FireEye Network Security (NX)
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """"uri_parsed":""", """"useragent":""", """"dstdomain":""" ]
  Fields = [
    """"eventtime":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"uri_parsed":\s{0,100}"({uri_path}[^"]{1,2000})""",
    """"srcipv4":\s{0,100}"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """"rcvdbodybytes":\s{0,100}({bytes_in}\d{1,100})""",
    """"sentbodybytes":\s{0,100}({bytes_out}\d{1,100})""",
    """"field":\s{0,100}"httpmethod/method"[^\}]{0,2000}?"value":\s{0,100}"({method}[^"]{1,2000})""",
    """""value":\s{0,100}"({method}[^"]{1,2000})"[^\}]{0,2000}?"field":\s{0,100}"httpmethod/method"""",
    """"dstipv4":\s{0,100}"({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """"statuscode":\s{0,100}({result_code}\d{1,100})""",
    """"dstport":\s{0,100}({dest_port}\d{1,100})""",
    """"srcport":\s{0,100}({src_port}\d{1,100})""",
    """"rawmsghostname":\s{0,100}"({host}[^"]{1,2000})""",
    """"dstdomain":\s{0,100}"({web_domain}[^"]{1,2000})""",
    """"useragent":\s{0,100}"({user_agent}[^"]{1,2000})""",
  ]


}
```