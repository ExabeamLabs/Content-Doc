#### Parser Content
```Java
{
Name = azure-file-read
  Vendor = Microsoft
  Product = Microsoft Azure
  Lms = Splunk
  DataType = "file-read"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """|resource-viewed|""","""|Skyformation|""","""destinationServiceName=Azure""" ]
  Fields = [
   """({time}\d+-\d+-\d+T\d+:\d+:\d+.\d+Z)""",
   """"ResourceProvider":"({object}[^"]+)""",
   """"ResourceId":"({file_path}({file_parent}(?:[^";]+)?[\/;])?({file_name}[^\/";]+))""""
   """"Resource":"({file_name}[^"]+)"""",
   """suser=((?i)anonymous|({user}[^\s]+))""",
   """devicePayloadId=.+\s+name\s+:\s+\[({host}[^\]]+)"""
   """fileType=({file_type}[^\s]+)""",
   """src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
   """"ResultType":"({outcome}[^"]+)""",
   """requestClientApplication=({app}.+?)\s\w+=""",
   """"OperationName":"({event_name}[^"]+)"""",
   """({accesses}resource-viewed)"""
   """msg=({additional_info}.+?)\s+\w+="""
  ]
}
```