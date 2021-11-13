#### Parser Content
```Java
{
Name = azure-file-read-2
  Product = Azure
  DataType = "file-read"
  Conditions= [ """destinationServiceName =Azure""", """"_ResourceId":"""", """"CorrelationId":"""", """dproc=Log Analytics OMS Workspace""", """"OperationName":"VaultGet"""" ]
  Fields = ${MSParserTemplates.azure-file-read.Fields} [
    """"ResourceId":"({file_path}({file_parent}(?:[^";]{1,2000})?[\/;])?({file_name}[^\/";]{1,2000}))"""",
  ]


azure-file-read = {
    Vendor = Microsoft
    Product = Azure
    Lms = Splunk
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Fields = [
      """"TimeGenerated":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
      """"ResourceProvider":"({object}[^"]{1,2000})""",
      """"ResourceId":"({file_path}({file_parent}(?:[^";]{1,2000})?[\/;])?({file_name}[^\/";]{1,2000}))"""",
      """"Resource":"({file_name}[^"]{1,2000})"""",
      """"id_s":"({file_path}({file_parent}(?:[^";]{1,2000})?[\/;])?({file_name}[^\/";]{1,2000})?)"""",
      """"SourceSystem":"({app}[^"]{1,2000})"""",
      """"CallerIPAddress":"({src_ip}[A-Fa-f\d:.]{1,2000})"""",
      """"ResultType":"({outcome}[^"]{1,2000})""",
      """"OperationName":"({event_name}[^"]{1,2000})"""",
      """"identity_claim_unique_name_s":"(({user_email}[^@"]{1,2000}@[^\.]{1,2000}\.[^"]{1,2000})|({user}[^"]{1,2000}))""""
    
}
```