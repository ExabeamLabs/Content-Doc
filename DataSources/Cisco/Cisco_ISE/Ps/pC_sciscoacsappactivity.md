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
      """exabeam_host=(::ffff:)?({host}[^\s]{1,2000})""",
      """User-Name =(?!host\/)(?:[a-f0-9]{12}|({user}[^,]{1,2000}))""",
      """NAS-IP-Address=(::ffff:)?({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """cmd=({activity}[^,]{1,2000})""",
      """_({app}TACACSAdmin)""",
      """priv-lvl=({privileges}[^,]{1,2000})""",
      """task_id=\w+@(::ffff:)?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
	]


}
```