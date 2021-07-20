#### Parser Content
```Java
{
Name = cef-netskope-app-activity-26
  DataType = "app-activity"
  Conditions = [ """CEF:""", """|Skyformation|""", """"type":"""", """destinationServiceName=Netskope""", """"activity":"Update StsRefreshTokenValidFrom Timestamp"""" ]
  DupFields = [ "activity->accesses", "object->file_name" ]
}
```