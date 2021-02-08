#### Parser Content
```Java
{
Name = cef-dropbox-app-activity-1
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """"file_operations"}""" ]
  Fields = ${DropboxParserTemplates.cef-dropbox-activity.Fields}[
    """"assets":\[[^\]]*?"display_name":"({object}[^",]+)"""",
    """"assets":\[[^\]]*?"contextual":"({resource}[^",]+)""""
  ]
}
```