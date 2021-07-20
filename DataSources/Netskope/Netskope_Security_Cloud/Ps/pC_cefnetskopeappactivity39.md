#### Parser Content
```Java
{
Name = cef-netskope-app-activity-39
  DataType = "app-activity"
  Conditions = [ """CEF:""", """|Skyformation|""", """"type":"""", """destinationServiceName=Netskope""", """"activity":"UPDATE_ACCESS_LEVEL_V2"""" ]
  DupFields = [ "activity->accesses", "object->file_name" ]
}
```