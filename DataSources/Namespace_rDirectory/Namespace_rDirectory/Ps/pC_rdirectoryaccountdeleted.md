#### Parser Content
```Java
{
Name = rdirectory-account-deleted
  Vendor = Namespace rDirectory
  Product = Namespace rDirectory
  Lms = Direct
  DataType = "account-deleted"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ "rdirectoryDelete:", "Modified by:" ]
  Fields = [
	"""SystemTime=\'({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
	"""<Computer>({host}[^<]{1,2000})""",
	"""Modified by:({user}.+?)\s{1,100}(\(.+?\))?\s{1,100}\(({domain}[^\/)]{1,2000})""",
	"""Credentials:({account_domain}[^\\]{1,2000})\\+([^\s.]{1,2000}\.)*({account}[^\s.]{1,2000})""",
	"""Delete:\s{0,100}({target_user}.+?)\s{1,100}\(({target_domain}[^\/)]{1,2000})"""
  ]
  DupFields = [ "host->dest_host" , "target_user->account_name"]
}
```