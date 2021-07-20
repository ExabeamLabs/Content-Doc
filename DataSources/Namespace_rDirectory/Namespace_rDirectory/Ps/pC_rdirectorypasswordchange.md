#### Parser Content
```Java
{
Name = rdirectory-password-change
  Vendor = Namespace rDirectory
  Product = Namespace rDirectory
  Lms = Direct
  DataType = "password-change"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ "rdirectorySet password:", "Modified by:" ]
  Fields = [
	"""SystemTime=\'({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
	"""<Computer>({host}[^<]{1,2000})""",
	"""Modified by:({user}.+?)\s{1,100}(\(.+?\))?\s{1,100}\(({domain}[^\/)]{1,2000})""",
	"""Credentials:({account_domain}[^\\]{1,2000})\\+([^\s.]{1,2000}\.)*({account}[^\s.]{1,2000})""",
	"""password:({target_user}.+?)\s{1,100}\(({target_domain}[^\/)]{1,2000})"""
  ]
  DupFields = [ "host->dest_host" ]
}
```