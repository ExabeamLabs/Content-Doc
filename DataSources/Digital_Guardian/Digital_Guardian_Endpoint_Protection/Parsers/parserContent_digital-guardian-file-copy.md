#### Parser Content
```Java
{
Name = digital-guardian-file-copy
  Product = Digital Guardian Endpoint Protection
  DataType = "file-write"
  Conditions = [ """ Agent_Local_Time="""", """ User_Name="""", """ Operation="11"""" ]
  Fields = ${DGParserTemplates.digital-guardian-activity.Fields}[
  ]
}
```