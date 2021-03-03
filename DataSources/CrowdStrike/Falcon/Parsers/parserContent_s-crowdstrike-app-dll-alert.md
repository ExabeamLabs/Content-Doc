#### Parser Content
```Java
{
Name = s-crowdstrike-app-dll-alert
  DataType = "alert"
  Conditions = [ """"event_simpleName":"ReflectiveDllLoaded"""", """|Skyformation|""" ]
  Fields = ${CrowdStrikeParserTemplates.cef-crowdstrike-app-activity-temp.Fields} [
  """"id":"({alert_id}[\w-]+?)"""",
  """"name":"({alert_name}[^"]+?)""""
  """"CommandLine"+:\s*"+\\*"*({command_line}.+?)\\*\s*"+,""",
  """"ImageFileName\\*"+:\\*"+({image_file_name}[^"]+?)\\*","""
  ]
}
```