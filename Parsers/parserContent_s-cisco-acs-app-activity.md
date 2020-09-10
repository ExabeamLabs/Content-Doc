#### Parser Content
```Java
{
Name = s-cisco-acs-app-activity
  Vendor = Cisco
  Product = Cisco ISE
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """_TACACSAdmin""", """service=""", """cmd=""" ]
  Fields = [  
      """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
      """exabeam_host=({host}[^\s]+)""",
      """User-Name=(?!host\/)(?:[a-f0-9]{12}|({user}[^,]+))""",
      """NAS-IP-Address=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """cmd=({activity}[^,]+)""",
      """_({app}TACACSAdmin)""",
      """priv-lvl=({privileges}[^,]+)""",
      """task_id=\w+@({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
	]
}
```