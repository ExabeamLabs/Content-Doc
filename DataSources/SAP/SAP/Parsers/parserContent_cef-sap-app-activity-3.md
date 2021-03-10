#### Parser Content
```Java
{
Name = cef-sap-app-activity-3
  DataType = "file-download"
  Conditions = [ """CEF:""", """|SAP|Security Audit Log|""", """AUY""" ]
  Fields = ${SAPParserTemplates.cef-sap-app-activity.Fields} [
    """oldFileName=({file_name}.*?)\s\w+="""
  ]
}
```