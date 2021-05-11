#### Parser Content
```Java
{
Name = rdirectory-object-modification
  Vendor = Namespace rDirectory
  Product = Namespace rDirectory
  Lms = Direct
  DataType = "ds-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ "rdirectoryModify User:", "Modified by:" ]
  Fields = [
	"""SystemTime=\'({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
	"""<Computer>({host}[^<]+)""",
	"""Modified by:({user}.+?)\s{1,100}(\(.+?\))?\s{1,100}\(({domain}[^\/)]+)""",
	"""Credentials:({account_domain}[^\\]+)\\+([^\s.]+\.)*({account}[^\s.]+)""",
	"""rdirectoryModify.+?\(.+?\)\[({attribute}[^\]]+)""",
	"""rdirectoryModify.+?\(.+?\)\[.+?\]\s{0,100}Add:({new_attribute}.+?)(\s{0,100}To:|<)""",
	"""rdirectoryModify.+?\(.+?\)\[.+?\]\s{0,100}Change:({old_attribute}.+?)\s{0,100}To:""",
	"""rdirectoryModify.+?\(.+?\)\[.+?\].+?To:({new_attribute}[^<\[]+)""",
	"""rdirectoryModify User:({object}.+?)\s{0,100}\("""
  ]
}
```