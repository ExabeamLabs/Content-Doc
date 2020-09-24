#### Parser Content
```Java
{
Name = digital-guardian-file-recycle
  DataType = "file-delete"
  Conditions = [ """ Agent_Local_Time="""", """ User_Name="""", """ Operation="17"""" ]
  Fields = ${DGParserTemplates.digital-guardian-activity.Fields}[
  ]
}
```