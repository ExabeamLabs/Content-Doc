#### Parser Content
```Java
{
Name = bitglass-failed-login
  Vendor = Bitglass
  Product = Bitglass CASB
  Lms = Splunk
  DataType = "failed-app-login"
  TimeFormat = "dd MMM yyyy HH:mm:ss"
  Conditions = [ """api.bitglass.com ""","""email=""",""""Failure, Login"""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """time=({time}\d{1,100} \w{1,10} \d\d\d\d \d\d:\d\d:\d\d)""",
    """user=({user_fullname}[^,]{1,2000})""",
    """email=({user_email}[^@\s,]{1,2000}@[^\s,]{1,2000})""",
    """application=({app}[^,]{1,2000})""",
    """ipaddress=({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """activity="({event_name}[^"]{1,2000})""",
    """details=({additional_info}[^,"]{1,2000})""",
    """usergroup="({user_group}[^"]{1,2000})""",
    """device=({os}[^",]{1,2000})""", 
    """details=({failure_reason}[^,.]{1,2000})""",
    """useragent=({user_agent}[^",]{1,2000})"""
	]


}
```