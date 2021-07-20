#### Parser Content
```Java
{
Name = cef-netskope-app-activity-35
  DataType = "app-activity"
  Conditions = [ """CEF:""", """|Skyformation|""", """"type":"""", """destinationServiceName=Netskope""", """"activity":"EMAIL_LOG_SEARCH"""" ]
  DupFields = [ "activity->accesses", "object->file_name" ]
}
```