#### Parser Content
```Java
{
Name = digital-guardian-send-mail
  DataType = "dlp-alert"
  Conditions = [ """ Agent_Local_Time="""", """ User_Name="""", """ Operation="28"""" ]
  Fields = ${DGParserTemplates.digital-guardian-activity.Fields}[
  ]
}
```