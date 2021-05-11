#### Parser Content
```Java
{
Name = rdirectory-member-added
  Vendor = Namespace rDirectory
  Product = Namespace rDirectory
  Lms = Direct
  DataType = "member-added"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ "rdirectoryModify Group:", "Modified by:", "[Member] Add:" ]
  Fields = [
	"""SystemTime=\'({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
	"""<Computer>({host}[^<]+)""",
	"""Modified by:({user}.+?)\s{1,100}(\(.+?\))?\s{1,100}\(({domain}[^\/)]+)""",
	"""Credentials:({account_used_domain}[^\\]+)\\+([^\s.]+\.)*({account}[^\s.]+)""",
	"""Group:({group_name}.+?)\s{1,100}\(({group_domain}[^\/)]+)""",
	"""\[Member\]\s{0,100}Add:CN=({account_name}[^,]+)""",
	"""\[Member\]\s{0,100}Add:({account_dn}CN=.+?,({account_ou}OU.+?DC=[\w-]+))""",
	"""\[Member\]\s{0,100}Add:(?:CN|({account_name}[^<]+))"""
  ]
}
```