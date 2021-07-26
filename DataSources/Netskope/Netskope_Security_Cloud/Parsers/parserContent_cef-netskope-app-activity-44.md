#### Parser Content
```Java
{
Name = cef-netskope-app-activity-44
  DataType = "app-activity"
  Conditions = [ """CEF:""", """|Skyformation|""", """"type":"""", """destinationServiceName=Netskope""", """"activity":"ALERT_CENTER_LIST_RELATED_ALERTS"""" ]
  DupFields = [ "activity->accesses", "object->file_name" ]
}
```