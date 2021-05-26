#### Parser Content
```Java
{
Name = symantec-epp-alert-chinese
  Vendor = Symantec
  Product = Symantec Endpoint Protection
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """,实际的操作:""",""",请求的操作:""" ]
  Fields = [
         """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
         """exabeam_host=({host}\S+)""",
         """计算机名:\s{0,100}(?:0+|({host}[^,]{1,2000}))""",
         """事件时间:\s{0,100}({time}[\d\- :]{1,2000})""",
         """({alert_type}(发现病毒|发现安全风险))""",
         """IP 地址:\s{0,100}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
         """风险名称:\s{0,100}({alert_name}[^,]{1,2000})""",
         """出现次数:\s{0,100}\d{1,100}
```