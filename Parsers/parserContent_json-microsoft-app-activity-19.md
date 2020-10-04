#### Parser Content
```Java
{
Name = json-microsoft-app-activity-19
  Product = Microsoft Office 365
  Conditions= [ """"Operation":"FileDeleted"""", """"Workload":"""", """"SourceFileName":"""" ]
  Fields = ${MSParserTemplates.cef-microsoft-app-activity.Fields} [
    """"ClientIP":"({src_ip}[^"]+)"""",
    """"SourceFileName":"({file_name}[^"]+)"""",
    """"SourceRelativeUrl":"({file_path}[^"]+)"""",
    """"SourceFileExtension":"({file_ext}[^"]+)"""",
    """"UserAgent":"({user_agent}[^"]+)""""
  ]
}
${MSParserTemplates.json-microsoft-app-activity} {
  Name = json-microsoft-app-activity-31
  Product = Microsoft Office 365
  Conditions= [ """"activityType":"Device"""", """"activityOperationType":"Update"""", """"targetResourceType":"""" ]
}
```