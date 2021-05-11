#### Parser Content
```Java
{
Name = rdirectory-account-enable
  Vendor = Namespace rDirectory
  Product = Namespace rDirectory
  Lms = Direct
  DataType = "account-enabled"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ "rdirectoryEnable account:", "Modified by:" ]
  Fields = [
	"""SystemTime=\'({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
	"""<Computer>({host}[^<]+)""",
	"""Modified by:({user}.+?)\s{1,100}(\(.+?\))?\s{1,100}\(({domain}[^\/)]+)""",
	"""Credentials:({account_domain}[^\\]+)\\+([^\s.]+\.)*({account}[^\s.]+)""",
	"""account:({target_user}.+?)\s{1,100}\(({target_domain}[^\/)]+)"""
  ]
  DupFields = ["host->src_host"]
}
```