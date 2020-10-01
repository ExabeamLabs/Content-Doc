#### Parser Content
```Java
{
Name = cef-netskope-file-operation-17
  DataType = "file-operations"
  Conditions = [ """CEF:""", """|Skyformation|""", """"type":"""", """destinationServiceName=Netskope""", """"activity":"FileModifiedExtended"""" ]
  DupFields = [ "activity->accesses", "object->file_name" ]
}
```