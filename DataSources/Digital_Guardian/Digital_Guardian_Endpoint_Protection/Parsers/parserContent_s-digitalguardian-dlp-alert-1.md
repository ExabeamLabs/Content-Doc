#### Parser Content
```Java
{
Name = s-digitalguardian-dlp-alert-1
  Conditions = [ """Rule_Violation="True"""", """Block_Code="Rule Block"""" ]
  Fields = ${DGParserTemplates.splunk-digitalguardian-dlp-alert.Fields}[
    """[^_]Custom_String_4="({alert_name}[^"]+)""",
    """[^_]Block_Code="({alert_type}[^"]+)""",
    """[^_]Bytes_Read="(?:|({bytes}[^"]+))"""",
  ]
}
```