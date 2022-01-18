#### Parser Content
```Java
{
Name = azure-file-read
  Vendor = Microsoft
  Product = Microsoft Azure
  Lms = Splunk
  DataType = "file-read"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """|resource-viewed|""","""|Skyformation|""","""destinationServiceName =Azure""" ]
  Fields = [
   """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}.\d{1,100}Z)""",
   """"ResourceProvider":"({object}[^"]{1,2000})""",
   """"ResourceId":"({file_path}({file_parent}(?:[^";]{1,2000})?[\/;])?({file_name}[^\/";]{1,2000}))""""
   """"Resource":"({file_name}[^"]{1,2000})"""",
   """suser=((?i)anonymous|({user}[^\s]{1,2000}))""",
   """devicePayloadId=.+\s{1,100}name\s{1,100}:\s{1,100}\[({host}[^\]]{1,2000})"""
   """fileType=({file_type}[^\s]{1,2000})""",
   """src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
   """"ResultType":"({outcome}[^"]{1,2000})""",
   """requestClientApplication=({app}.+?)\s\w+=""",
   """"OperationName":"({event_name}[^"]{1,2000})"""",
   """({accesses}resource-viewed)"""
   """msg=({additional_info}.+?)\s{1,100}\w+="""
  ]


}
```