#### Parser Content
```Java
{
Name = cef-microsoft-app-activity-34
  Product = Office 365
  Conditions= [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """destinationServiceName=Office 365""", """flexString1=RefreshDataset""" ]
  Fields = ${MSParserTemplates.cef-microsoft-app-activity.Fields}[
     """ext_ObjectId=({object}.+?)\s\w+="""
  ]
}
```