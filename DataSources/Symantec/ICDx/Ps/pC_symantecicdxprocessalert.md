#### Parser Content
```Java
{
Name = symantec-icdx-process-alert
  Vendor = Symantec
  Product = ICDx
  Lms = Direct
  DataType = "process-alert"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Symantec|ICDx|""", """"type":"HOST_PROCESS_DETECTION"""", """"product_name":"Symantec Integrated Cyber Defense Manager"""" ]
  Fields = [
  """"device_time":({time}\d{13})"""
  """\w{3,4} \d{1,2}\s\d{1,2}:\d{1,2}:\d{1,2}\s({host}[\w\-.]{1,2000})\s"""
  """dvchost=({src_host}[\w\-.]{1,2000})"""
  """suser=(none|SYSTEM|({user}[^\s]{1,2000}))"""
  """dvc=({dest_ip}[A-Fa-f\d:.]{1,2000})"""
  """cs3Label=({alert_name}[^=]{1,2000}?)\s{0,20}\w+="""
  """"type":"({alert_type}[^"]{1,2000})""""
  """"process":[^\}]{1,2000}"path":"({process}({directory}(?:[^"]{1,2000})?[\\\/])?({process_name}[^\\\/"]{1,2000}?))""""
  """"uid":"({user_id}[^"]{1,2000})"""
  """Symantec\|([^=]{1,2000})\|({alert_severity}\w{1,100})\|\w+="""
  """spt=({src_port}\d{1,5})"""
  """dpt=({dest_port}\d{1,5})"""
  """"device_domain":"({domain}[^"]{1,2000})""""
  """\sproto=({protocol}[^\s]{1,2000})\s"""
  """"md5":"({md5}[^"]{1,2000})""""
  ]
  DupFields = ["directory->process_directory"]


}
```