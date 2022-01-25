#### Parser Content
```Java
{
Name = s-cisco-acs-auth-successful
  Vendor = Cisco
  Product = Cisco ISE
  Lms = Splunk
  DataType = "authentication-successful"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Message-Type=Authen OK""", """_PassedAuth""" ]
  Fields = [ 
      """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
      """exabeam_host=(::ffff:)?({host}[^\s]{1,2000})""",
      """Caller-ID=(::ffff:)?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """User-Name=(?!host\/)(?:[a-f0-9]{12}|({user}[^,]{1,2000}))""",
      """NAS-IP-Address=(::ffff:)?({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
	]
}
```