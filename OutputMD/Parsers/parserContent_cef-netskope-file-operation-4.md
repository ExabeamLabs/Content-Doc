#### Parser Content
```Java
{
Name = cef-netskope-file-operation-4
  DataType = "file-operations"
  Conditions = [ """CEF:""", """|Skyformation|""", """"type":"""", """destinationServiceName=Netskope""", """"activity":"Delete"""", """"object_type":"File"""" ]
  DupFields = [ "activity->accesses", "object->file_name" ]
}
```