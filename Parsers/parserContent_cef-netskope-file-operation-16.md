#### Parser Content
```Java
{
Name = cef-netskope-file-operation-16
  DataType = "file-operations"
  Conditions = [ """CEF:""", """|Skyformation|""", """"type":"""", """destinationServiceName=Netskope""", """"activity":"FileAccessedExtended"""" ]
  DupFields = [ "activity->accesses", "object->file_name" ]
}
```