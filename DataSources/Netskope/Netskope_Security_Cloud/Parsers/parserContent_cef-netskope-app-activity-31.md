#### Parser Content
```Java
{
Name = cef-netskope-app-activity-31
  DataType = "app-activity"
  Conditions = [ """CEF:""", """|Skyformation|""", """"type":"""", """destinationServiceName=Netskope""", """"activity":"CREATE_GMAIL_SETTING"""" ]
  DupFields = [ "activity->accesses", "object->file_name" ]
}
```