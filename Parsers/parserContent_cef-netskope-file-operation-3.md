#### Parser Content
```Java
{
Name = cef-netskope-file-operation-3
  DataType = "file-operations"
  Conditions = [ """CEF:""", """|Skyformation|""", """"type":"""", """destinationServiceName=Netskope""", """"activity":"Create"""", """"object_type":"File"""" ]
  DupFields = [ "activity->accesses", "object->file_name" ]
}
```