#### Parser Content
```Java
{
Name = json-veritas-file-operations
  Vendor = Veritas
  Product = Data Insight
  Lms = Splunk
  DataType = "file-operations"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """"UserId":""", """"ClientIP":""", """"ObjectId":""", """"DeviceName": """ ]
  Fields = [
  """"CreationTime":\s"({time}\d{4}-\d{1,2}-\d{1,2}T\d{1,2}:\d{1,2}:\d{1,2})"""
  """DeviceName":\s"({host}[\w\-.]{1,2000})""""
  """"ClientIP":\s"({src_ip}[a-fA-F\d:\.]{1,2000})""""
  """"ApplicationName":\s"({app}[^"]{1,2000})""""
  """"ProcessName":\s"({process_name}[^"]{1,2000})""""
  """"Operation":\s"({activity}[^"]{1,2000})""""
  """"UserId":\s"(({user_email}[^"@]{1,2000}@[^"@]{1,2000}\.[^"]{1,2000})|({user}[^"]{1,2000}))""""
  """"ObjectId":\s"([\\]{1,100})?({file_path}({file_parent}[^"]{1,2000})\\({file_name}[^"]{1,2000}\.({file_ext}\w+)))""""
  """"Id":\s"({object_id}[^"]{1,2000})""""
  ]
  DupFields = [ "host->src_host" ]


}
```