#### Parser Content
```Java
{
Name = netdoc-app-activity-1
 Product = NetDocs
 Vendor = NetDocs
 Lms = Splunk
 TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
 DataType = "app-activity"
 Conditions = [ """netdocs""", """memberType": """, """storageObject":""", """cabinet": """ ]
 Fields =[
   """"{1,20}host"{1,20}:\s"{1,20}({host}[^"]{1,2000})"{1,20}
```