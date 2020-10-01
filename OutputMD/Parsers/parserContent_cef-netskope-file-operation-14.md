#### Parser Content
```Java
{
Name = cef-netskope-file-operation-14
  DataType = "file-operations"
  Conditions = [ """CEF:""", """|Skyformation|""", """"type":"""", """destinationServiceName=Netskope""", """"activity":"View"""", """"object_type":"File"""" ]
  DupFields = [ "activity->accesses", "object->file_name" ]
}
```