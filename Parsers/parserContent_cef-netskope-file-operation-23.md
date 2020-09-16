#### Parser Content
```Java
{
Name = cef-netskope-file-operation-23
  DataType = "file-operations"
  Conditions = [ """CEF:""", """|Skyformation|""", """"type":"""", """destinationServiceName=Netskope""", """"activity":"FileDeleted""" ]
  DupFields = [ "activity->accesses", "object->file_name" ]
}
```