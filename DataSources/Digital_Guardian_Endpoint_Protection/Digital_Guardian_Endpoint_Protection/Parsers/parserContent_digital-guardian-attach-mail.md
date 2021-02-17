#### Parser Content
```Java
{
Name = digital-guardian-attach-mail
  Product = Digital Guardian Endpoint Protection
  DataType = "file-upload"
  Conditions = [ """ Agent_Local_Time="""", """ User_Name="""", """ Operation="36"""" ]
  Fields = ${DGParserTemplates.digital-guardian-activity.Fields}[
  ]
}
```