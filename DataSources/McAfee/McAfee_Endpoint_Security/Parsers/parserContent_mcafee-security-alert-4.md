#### Parser Content
```Java
{
Name = mcafee-security-alert-4
  DataType = "alert"
  Conditions = [ """productname=VirusScan Enterprise""" ]
  Fields = ${McAfeeParserTemplates.mcafee-dlp-alert.Fields}[
    """serverhostname=({host}[^,]+)""",
  ]
}
```