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
	"""<Computer>({host}[^<]+)""",
	"""Modified by:({user}.+?)\s{1,100}(\(.+?\))?\s{1,100}\(({domain}[^\/)]+)""",
	"""Credentials:({account_domain}[^\\]+)\\+([^\s.]+\.)*({account}[^\s.]+)""",
	"""Delete:\s{0,100}({target_user}.+?)\s{1,100}\(({target_domain}[^\/)]+)"""
  ]
  DupFields = [ "host->dest_host" , "target_user->account_name"]
}
```