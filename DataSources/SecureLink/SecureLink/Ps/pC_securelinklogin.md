#### Parser Content
```Java
{
Name = securelink-login
  DataType = "app-login"
  Conditions = [  """ Logged in.""", """SecureLink:""", """User:""" ]
  Fields = ${SecureLinkParserTemplates.securelink-events.Fields}[
  """({event_name}Logged in)"""
  ]

securelink-events {
     Vendor = SecureLink
     Product = SecureLink
     Lms = Direct
     TimeFormat = "yyyy-MM-dd HH:mm:ss"
     Fields = [
	 """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
	 """exabeam_host=({host}[\w.\-]{1,2000})""",
	 """User:\s{0,100}(SYSLOG|(({user}[^"@\\\/\s,]{1,2000})(@({domain}[^,]{1,2000}))?))""",
	 """Text:\s{0,100}\[({src_ip}[A-Fa-f:\d.]{1,2000})""",
	 """Key:\s{0,100}({user_email}({user}[^"@\\\/\s,]{1,2000})(@({domain}[^,]{1,2000}))?)""", 
     
}
```