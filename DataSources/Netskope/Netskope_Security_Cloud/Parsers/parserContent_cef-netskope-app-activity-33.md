#### Parser Content
```Java
{
Name = cef-netskope-app-activity-33
  DataType = "app-activity"
  Conditions = [ """CEF:""", """|Skyformation|""", """"type":"""", """destinationServiceName=Netskope""", """"activity":"DELETE_GMAIL_SETTING"""" ]
  DupFields = [ "activity->accesses", "object->file_name" ]
}
```