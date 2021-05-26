#### Parser Content
```Java
{
Name = cef-netskope-app-activity-25
  DataType = "app-activity"
  Conditions = [ """CEF:""", """|Skyformation|""", """"type":"""", """destinationServiceName=Netskope""", """"activity":"SearchQueryPerformed"""" ]
  DupFields = [ "activity->accesses", "object->file_name" ]
}
```