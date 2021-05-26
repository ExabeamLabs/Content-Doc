#### Parser Content
```Java
{
Name = cef-netskope-app-activity-27
  DataType = "app-activity"
  Conditions = [ """CEF:""", """|Skyformation|""", """"type":"""", """destinationServiceName=Netskope""", """"activity":"ALERT_CENTER_VIEW"""" ]
  DupFields = [ "activity->accesses", "object->file_name" ]
}
```