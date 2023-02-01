#### Parser Content
```Java
{
Name = azure-blob-activity2
   Vendor = Microsoft
   Product = Microsoft Azure
   Lms = Direct
   DataType = "azure-general-activity"
   TimeFormat = """yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"""
   Conditions = [ """serviceType":"blob""", """operationName""" ] 
 }  

${MSParserTemplates.azure-workspacekeyault-json}{
   Name = azure-keyvault-activity
   Vendor = Microsoft
   Product = Microsoft Azure
   Lms = Direct
   DataType = "azure-general-activity"
   TimeFormat = """yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"""
   Conditions = [ """Type":"AzureDiagnostics""", """ResourceProvider":"MICROSOFT.KEYVAULT""", """OperationName""" ] 
 

}
```