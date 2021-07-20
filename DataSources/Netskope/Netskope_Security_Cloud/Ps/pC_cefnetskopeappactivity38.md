#### Parser Content
```Java
{
Name = cef-netskope-app-activity-38
  DataType = "app-activity"
  Conditions = [ """CEF:""", """|Skyformation|""", """"type":"""", """destinationServiceName=Netskope""", """"activity":"SECURITY_INVESTIGATION_QUERY"""" ]
  DupFields = [ "activity->accesses", "object->file_name" ]
}
```