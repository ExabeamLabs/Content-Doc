#### Parser Content
```Java
{
Name = s-crowdstrike-app-ransomware
  DataType = "alert"
  Conditions = [ """"event_simpleName":"RansomwareOpenFile"""", """|Skyformation|""" ]
  Fields = ${CrowdStrikeParserTemplates.cef-crowdstrike-app-activity-temp.Fields} [
  """"id":"({alert_id}[\w-]+?)"""",
  """"name":"({alert_name}[^"]+?)""""
  ]
  DupFields = ["file_path->additional_info"]
}
```