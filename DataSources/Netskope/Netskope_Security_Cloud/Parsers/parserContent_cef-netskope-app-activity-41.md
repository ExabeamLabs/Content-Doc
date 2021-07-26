#### Parser Content
```Java
{
Name = cef-netskope-app-activity-41
  DataType = "app-activity"
  Conditions = [ """CEF:""", """|Skyformation|""", """"type":"""", """destinationServiceName=Netskope""", """"activity":"ALERT_CENTER_GET_SIT_LINK"""" ]
  DupFields = [ "activity->accesses", "object->file_name" ]
}
```