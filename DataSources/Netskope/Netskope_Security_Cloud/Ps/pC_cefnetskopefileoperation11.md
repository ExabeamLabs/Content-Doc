#### Parser Content
```Java
{
Name = cef-netskope-file-operation-11
  DataType = "file-operations"
  Conditions = [ """CEF:""", """|Skyformation|""", """"type":"""", """destinationServiceName=Netskope""", """"activity":"Preview"""", """"object_type":"File"""" ]
  DupFields = [ "activity->accesses", "object->file_name" ]
}
```