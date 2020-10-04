#### Parser Content
```Java
{
Name = json-microsoft-app-activity-11
  Product = Microsoft Office 365
  Conditions= [ """"activityType":"User"""", """"activityOperationType":"Restore"""", """"targetResourceType":"""" ]
}
${MSParserTemplates.json-microsoft-app-activity} {
  Name = json-microsoft-app-activity-12
  Product = Microsoft Office 365
  Conditions= [ """"activityType":"User"""", """"activityOperationType":"Update"""", """"targetResourceType":"""" ]
}
${MSParserTemplates.json-microsoft-app-activity} {
  Name = json-o365-file-write-7
  Product = Microsoft Office 365
  Conditions= [ """"Operation":"FileUploaded"""", """"Workload":"""", """"SourceFileName":"""" ]
}
```