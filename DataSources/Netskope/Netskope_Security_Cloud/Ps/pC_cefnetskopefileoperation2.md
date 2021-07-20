#### Parser Content
```Java
{
Name = cef-netskope-file-operation-2
  DataType = "file-operations"
  Conditions = [ """CEF:""", """|Skyformation|""", """"type":"""", """destinationServiceName=Netskope""", """"activity":"Introspection Scan"""", """"object_type":"File"""" ]
  DupFields = [ "activity->accesses", "object->file_name" ]
}
```