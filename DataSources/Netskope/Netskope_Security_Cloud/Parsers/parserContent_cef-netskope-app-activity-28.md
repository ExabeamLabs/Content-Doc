#### Parser Content
```Java
{
Name = cef-netskope-app-activity-28
  DataType = "app-activity"
  Conditions = [ """CEF:""", """|Skyformation|""", """"type":"""", """destinationServiceName=Netskope""", """"activity":"ARCHIVE_USER"""" ]
  DupFields = [ "activity->accesses", "object->file_name" ]
}
```